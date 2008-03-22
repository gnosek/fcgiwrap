#define NO_FCGI_DEFINES

#include <stdarg.h>
#include <fcgi_stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/select.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <limits.h>

extern char **environ;
static char * const * inherited_environ;

static const char * blacklisted_env_vars[] = {
	"AUTH_TYPE",
	"CONTENT_LENGTH",
	"CONTENT_TYPE",
	"GATEWAY_INTERFACE",
	"PATH_INFO",
	"PATH_TRANSLATED",
	"QUERY_STRING",
	"REMOTE_ADDR",
	"REMOTE_HOST",
	"REMOTE_IDENT",
	"REMOTE_USER",
	"REQUEST_METHOD",
	"SCRIPT_NAME",
	"SERVER_NAME",
	"SERVER_PORT",
	"SERVER_PROTOCOL",
	"SERVER_SOFTWARE",
	NULL,
};


#define FCGI_BUF_SIZE 4096

static int write_all(int fd, char *buf, size_t size)
{
	size_t nleft = size;
	while (nleft > 0) {
		ssize_t nwritten = write(fd, buf, nleft);
		if (nwritten < 0)
			return nleft - size; /* zero or negative to indicate error */

		buf += nwritten;
		nleft -= nwritten;
	}

	return size;
}

#define MAX_VA_SENTINEL INT_MIN

static int max_va(int p1, ...)
{
	va_list va;
	int max = p1;
	int p;

	va_start(va, p1);
	do {
		p = va_arg(va, int);
		if (p > max)
			max = p;
	} while (p != MAX_VA_SENTINEL);
	va_end(va);

	return max;
}

enum reply_state_t {
	REPLY_STATE_INIT,
	REPLY_STATE_HEADER,
	REPLY_STATE_CR,
	REPLY_STATE_LF,
	REPLY_STATE_2CR,
	REPLY_STATE_2LF,
	REPLY_STATE_BODY,
	REPLY_STATE_MAX
};

enum char_class_t {
	CC_NORMAL,
	CC_CR,
	CC_LF,
	CC_MAX
};

#define ACTION_MASK	(15 << 4)
#define ACTION_EMIT	0
#define ACTION_ERROR	(1 << 4)
#define ACTION_END	(2 << 4)
#define ACTION_SKIP	(3 << 4)
#define ACTION_EXTRA_CR	(4 << 4)
#define ACTION_EXTRA_LF	(5 << 4)

static const unsigned char header_state_machine[REPLY_STATE_MAX][CC_MAX] = {
	[REPLY_STATE_INIT] = {
		[CC_NORMAL] = REPLY_STATE_HEADER,
		[CC_CR] = ACTION_ERROR,
		[CC_LF] = ACTION_ERROR,
	},
	[REPLY_STATE_HEADER] = {
		[CC_NORMAL] = REPLY_STATE_HEADER,
		[CC_CR] = REPLY_STATE_CR,
		[CC_LF] = REPLY_STATE_LF | ACTION_EXTRA_CR,
	},
	[REPLY_STATE_CR] = {
		[CC_NORMAL] = REPLY_STATE_HEADER | ACTION_EXTRA_LF,
		[CC_CR] = REPLY_STATE_CR | ACTION_SKIP,
		[CC_LF] = REPLY_STATE_LF,
	},
	[REPLY_STATE_LF] = {
		[CC_NORMAL] = REPLY_STATE_HEADER,
		[CC_CR] = REPLY_STATE_2CR,
		[CC_LF] = REPLY_STATE_2LF | ACTION_EXTRA_CR,
	},
	[REPLY_STATE_2CR] = {
		[CC_NORMAL] = REPLY_STATE_BODY | ACTION_EXTRA_LF,
		[CC_CR] = REPLY_STATE_CR | ACTION_SKIP,
		[CC_LF] = REPLY_STATE_2LF,
	},
	[REPLY_STATE_2LF] = {
		[CC_NORMAL] = REPLY_STATE_BODY | ACTION_END,
		[CC_CR] = REPLY_STATE_2LF | ACTION_SKIP,
		[CC_LF] = REPLY_STATE_2LF | ACTION_SKIP,
	},
};

struct fcgi_context {
	int fd_stdin;
	int fd_stdout;
	int fd_stderr;
	unsigned int reply_state;
	pid_t cgi_pid;
};

static void fcgi_finish(struct fcgi_context *fc, const char* msg)
{
	if (fc->reply_state == REPLY_STATE_INIT) {
		FCGI_puts("Status: 502 Bad Gateway\nContent-type: text/plain\n");
		FCGI_printf("An error occurred while %s\n", msg);
	}

	if (fc->fd_stdin >= 0) close(fc->fd_stdin);
	if (fc->fd_stdout >= 0) close(fc->fd_stdout);
	if (fc->fd_stderr >= 0) close(fc->fd_stderr);

	if (fc->cgi_pid)
		kill(SIGTERM, fc->cgi_pid);
}

static const char * fcgi_pass_fd(struct fcgi_context *fc, int *fdp, FCGI_FILE *ffp, char *buf, size_t bufsize)
{
	ssize_t nread;
	char *p = buf;
	unsigned char cclass, next_state;

	nread = read(*fdp, buf, bufsize);
	if (nread > 0) {
		while (p < buf + nread) {
			if (*p == '\r') {
				cclass = CC_CR;
			} else if (*p == '\n') {
				cclass = CC_LF;
			} else {
				cclass = CC_NORMAL;
			}
			next_state = header_state_machine[fc->reply_state][cclass];
			fc->reply_state = next_state & ~ACTION_MASK;
			switch(next_state & ACTION_MASK) {
				case ACTION_ERROR:
					return "parsing CGI reply";

				case ACTION_END:
					goto out_of_loop;

				case ACTION_SKIP:
					goto next_char;

				case ACTION_EXTRA_CR:
					if (FCGI_fputc('\r', ffp) == EOF) return "writing CGI reply";
					break;

				case ACTION_EXTRA_LF:
					if (FCGI_fputc('\n', ffp) == EOF) return "writing CGI reply";
					break;
			}
			if (FCGI_fputc(*p, ffp) == EOF) {
				return "writing CGI reply";
			}
next_char:
			p++;
		}
out_of_loop:
		if (p < buf + nread) {
			if (FCGI_fwrite(p, 1, buf + nread - p, ffp) != (size_t)(buf + nread - p)) {
				return "writing CGI reply";
			}
		}
	} else {
		if (nread < 0) {
			return "reading CGI reply";
		}
		close(*fdp);
		*fdp = -1;
	}

	return NULL;
}

static const char * fcgi_pass_raw_fd(int *fdp, int fd_out, char *buf, size_t bufsize)
{
	ssize_t nread;

	nread = read(*fdp, buf, bufsize);
	if (nread > 0) {
		if (write_all(fd_out, buf, nread) != nread) {
			return "writing CGI reply";
		}
	} else {
		if (nread < 0) {
			return "reading CGI reply";
		}
		close(*fdp);
		*fdp = -1;
	}
	return NULL;
}

static void fcgi_pass(struct fcgi_context *fc)
{
	char buf[FCGI_BUF_SIZE];
	ssize_t nread;
	fd_set rset;
	int maxfd = 1 + max_va(fc->fd_stdout, fc->fd_stderr, MAX_VA_SENTINEL);
	int nready;
	const char *err;

	/* eat the whole request and pass it to CGI */
	while ((nread = FCGI_fread(buf, 1, sizeof(buf), FCGI_stdin)) > 0) {
		if (write_all(fc->fd_stdin, buf, nread) <= 0) {
			fcgi_finish(fc, "reading the request");
			return;
		}
	}
	close(fc->fd_stdin);
	fc->fd_stdin = -1;

	/* now pass CGI reply back */
	while (fc->fd_stdout >= 0 && fc->fd_stderr >= 0) {
		FD_ZERO(&rset);
		if (fc->fd_stdout >= 0) FD_SET(fc->fd_stdout, &rset);
		if (fc->fd_stderr >= 0) FD_SET(fc->fd_stderr, &rset);
		nready = select(maxfd, &rset, NULL, NULL, NULL);
		if (nready < 0) {
			if (errno == EAGAIN) continue;
			fcgi_finish(fc, "waiting for CGI reply");
			return;
		}
		if (fc->fd_stdout >= 0 && FD_ISSET(fc->fd_stdout, &rset)) {
			err = fcgi_pass_fd(fc, &fc->fd_stdout, FCGI_stdout, buf, sizeof(buf));
			if (err) {
				fcgi_finish(fc, err);
				return;
			}
		}
		if (fc->fd_stderr >= 0 && FD_ISSET(fc->fd_stderr, &rset)) {
			err = fcgi_pass_raw_fd(&fc->fd_stderr, 2, buf, sizeof(buf));
			if (err) {
				fcgi_finish(fc, err);
				return;
			}
		}
	}

	fc->cgi_pid = 0;

	fcgi_finish(fc, "reading CGI reply (no response received)");
}

int check_file_perms(const char *path)
{
	struct stat ls;
	struct stat fs;

	if (lstat(path, &ls) < 0) {
		return -ENOENT;
	} else if (S_ISREG(ls.st_mode)) {
		if (ls.st_mode & S_IXUSR) {
			return 0;
		} else {
			return -EACCES;
		}
	} else if (!S_ISLNK(ls.st_mode)) {
		return -EACCES;
	}

	if (stat(path, &fs) < 0) {
		return -ENOENT;
	} else if (S_ISREG(fs.st_mode)) {
		if (fs.st_mode & S_IXUSR) {
			return 0;
		} else {
			return -EACCES;
		}
	} else {
		return -EACCES;
	}
}

char *get_cgi_filename() /* and fixup environment */
{
	int buflen = 1, docrootlen;
	char *buf = NULL;
	char *docroot, *scriptname, *p;

	int rf_len;
	char *pathinfo = NULL;

	if ((p = getenv("DOCUMENT_ROOT"))) {
		docroot = p;
		buflen += docrootlen = strlen(p);
	} else {
		goto err;
	}

	if ((p = getenv("SCRIPT_NAME"))) {
		buflen += strlen(p);
		scriptname = p;
	} else {
		goto err;
	}

	buf = malloc(buflen);
	if (!buf) goto err;

	strcpy(buf, docroot);
	strcpy(buf + docrootlen, scriptname);
	pathinfo = strdup(buf);
	if (!pathinfo) {
		goto err;
	}

	while(1) {
		switch(check_file_perms(buf)) {
			case -EACCES:
				goto err;
			case 0:
				rf_len = strlen(buf);
				if (rf_len < buflen - 1) {
					setenv("PATH_INFO", pathinfo + rf_len, 1);
					setenv("SCRIPT_NAME", buf + docrootlen, 1);
				} else {
					unsetenv("PATH_INFO");
				}
				free(pathinfo);
				return buf;
			default:
				p = strrchr(buf, '/');
				if (!p) goto err;
				*p = 0;
		}
	}

err:
	free(pathinfo);
	free(buf);
	return NULL;
}

static int blacklisted_env(const char *var_name, const char *var_name_end)
{
	const char **p;

	if (var_name_end - var_name > 4 && !strncmp(var_name, "HTTP", 4)) {
		/* HTTP_*, HTTPS */
		return 1;
	}

	for (p = blacklisted_env_vars; *p; p++) {
		if (!strcmp(var_name, *p)) {
			return 1;
		}
	}

	return 0;
}

static void inherit_environment()
{
	char * const * p;
	char *q;

	for (p = inherited_environ; *p; p++) {
		q = strchr(*p, '=');
		if (!q) {
			fprintf(stderr, "Suspect value in environment: %s\n", *p);
			continue;
		}
		*q = 0;

		if (!getenv(*p) && !blacklisted_env(*p, q)) {
			*q = '=';
			putenv(*p);
		}

		*q = '=';
	}
}

static void handle_fcgi_request()
{
	int pipe_in[2];
	int pipe_out[2];
	int pipe_err[2];
	char *filename;
	char *last_slash;
	pid_t pid;

	struct fcgi_context fc;

	if (pipe(pipe_in) < 0) goto err_pipein;
	if (pipe(pipe_out) < 0) goto err_pipeout;
	if (pipe(pipe_err) < 0) goto err_pipeerr;

	switch((pid = fork())) {
		case -1:
			goto err_fork;

		case 0: /* child */
			filename = get_cgi_filename();
			inherit_environment();
			if (!filename) {
				puts("Status: 403 Forbidden\nContent-type: text/plain\n\n403");
				exit(99);
			}

			last_slash = strrchr(filename, '/');
			if (!last_slash) {
				puts("Status: 403 Forbidden\nContent-type: text/plain\n\n403");
				exit(99);
			}

			*last_slash = 0;
			if (chdir(filename) < 0) {
				puts("Status: 403 Forbidden\nContent-type: text/plain\n\n403");
				exit(99);
			}
			*last_slash = '/';

			close(pipe_in[1]);
			close(pipe_out[0]);
			close(pipe_err[0]);

			dup2(pipe_in[0], 0);
			dup2(pipe_out[1], 1);
			dup2(pipe_err[1], 2);

			execl(filename, filename, NULL);
			puts("Status: 502 Bad Gateway\nContent-type: text/plain\n\n502");
			exit(99);

		default: /* parent */
			close(pipe_in[0]);
			close(pipe_out[1]);
			close(pipe_err[1]);

			fc.fd_stdin = pipe_in[1];
			fc.fd_stdout = pipe_out[0];
			fc.fd_stderr = pipe_err[0];
			fc.reply_state = REPLY_STATE_INIT;
			fc.cgi_pid = pid;

			fcgi_pass(&fc);
	}
	return;

err_fork:
	close(pipe_err[0]);
	close(pipe_err[1]);

err_pipeerr:
	close(pipe_out[0]);
	close(pipe_out[1]);

err_pipeout:
	close(pipe_in[0]);
	close(pipe_in[1]);

err_pipein:

	FCGI_puts("Status: 502 Bad Gateway\nContent-type: text/plain\n");
	FCGI_puts("System error");
}

int main(/* int argc, char **argv */)
{
	signal(SIGCHLD, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);

	inherited_environ = environ;

	while (FCGI_Accept() >= 0) {
		handle_fcgi_request();
	}

	return 0;
}


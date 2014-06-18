/*
 * Copyright (c) 2007-2013 Grzegorz Nosek
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#define NO_FCGI_DEFINES

#include "config.h"
#include <stdarg.h>
#include <fcgi_stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/select.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

/* glibc doesn't seem to export it */
#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

#define LENGTH(x) (sizeof(x) / sizeof((x)[0]))

extern char **environ;
static char * const * inherited_environ;
static const char **allowed_programs;
static size_t allowed_programs_count;

static const char * const blacklisted_env_vars[] = {
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
	"SERVER_SOFTWARE"
};

static bool stderr_to_fastcgi = false;


#define FCGI_BUF_SIZE 4096

static ssize_t write_all(int fd, char *buf, size_t size)
{
	/* Assume that size <= SSIZE_MAX */
	ssize_t nleft = (ssize_t)size;
	while (nleft > 0) {
		ssize_t nwritten = write(fd, buf, nleft);
		if (nwritten < 0)
			return nleft - (ssize_t)size; /* zero or negative to indicate error */

		buf += nwritten;
		nleft -= nwritten;
	}

	return (ssize_t)size;
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
		[CC_CR] = REPLY_STATE_BODY | ACTION_END,
		[CC_LF] = REPLY_STATE_BODY | ACTION_END,
	},
	[REPLY_STATE_BODY] = {
		[CC_NORMAL] = REPLY_STATE_BODY | ACTION_END,
		[CC_CR] = REPLY_STATE_BODY | ACTION_END,
		[CC_LF] = REPLY_STATE_BODY | ACTION_END,
	},
};

struct fcgi_context {
	int fd_stdin;
	int fd_stdout;
	int fd_stderr;
	enum reply_state_t reply_state;
	pid_t cgi_pid;
};

static size_t fcgi_fwrite(void *ptr, size_t size, size_t nmemb, FCGI_FILE *fp, bool *error)
{
	size_t n;

	n = FCGI_fwrite(ptr, size, nmemb, fp);
	/* FCGI_fwrite ignores that FCGX_PutStr can return -1. It divides the
	 * result of a call to FCGX_PutStr by size. So it is necessary to check
	 * that the result of FCGI_fwrite is not equal to -1 / size. It could be
	 * that -1 / size is also a valid size_t value and that this check is a
	 * false positive but it is better to fail than to proceed with an
	 * invalid value.
	 */
	/* FCGI_fwrite can return (size_t)EOF. EOF is defined to be negative,
	 * but size_t is unsigned. So it is necessary to check that the result
	 * of FCGI_fwrite is not equal to (size_t)EOF. It could be that
	 * (size_t)EOF is also a valid size_t value and that this check is a
	 * false positive but it is better to fail than to proceed with an
	 * invalid value.
	 */
	if (n == -1 / size || n == (size_t)EOF) {
		*error = true;
		/* If error is true, the return value is ignored. So the return
		 * value is irrelevant.
		 */
		return 0;
	} else {
		*error = false;
		return n;
	}
}

static size_t fcgi_fread(void *ptr, size_t size, size_t nmemb, FCGI_FILE *fp, bool *error)
{
	size_t n;

	n = FCGI_fread(ptr, size, nmemb, fp);
	/* FCGI_fread can return (size_t)EOF. EOF is defined to be negative,
	 * but size_t is unsigned. So it is necessary to check that the result
	 * of FCGI_fwrite is not equal to (size_t)EOF. It could be that
	 * (size_t)EOF is also a valid size_t value and that this check is a
	 * false positive but it is better to fail than to proceed with an
	 * invalid value.
	 */
	if (n == (size_t)EOF) {
		*error = true;
		/* If error is true, the return value is ignored. So the return
		 * value is irrelevant.
		 */
		return 0;
	} else {
		*error = false;
		return n;
	}
}

static void fcgi_finish(struct fcgi_context *fc, const char* msg)
{
	if (fc->reply_state == REPLY_STATE_INIT) {
		(void)FCGI_puts("Status: 502 Bad Gateway\nContent-type: text/plain\n");
		(void)FCGI_printf("An error occurred while %s\n", msg);
	}

	if (fc->fd_stdin >= 0) (void)close(fc->fd_stdin);
	if (fc->fd_stdout >= 0) (void)close(fc->fd_stdout);
	if (fc->fd_stderr >= 0) (void)close(fc->fd_stderr);

	if (fc->cgi_pid > 0)
		(void)kill(fc->cgi_pid, SIGTERM);
}

static const char *fcgi_pass_fd(struct fcgi_context *fc, int *fdp, FCGI_FILE *ffp, char *buf, size_t bufsize)
{
	ssize_t nread;
	char *p = buf;
	enum char_class_t cclass;
	enum reply_state_t next_state;

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
					if (FCGI_fputc((int)'\r', ffp) == EOF) return "writing CGI reply";
					break;

				case ACTION_EXTRA_LF:
					if (FCGI_fputc((int)'\n', ffp) == EOF) return "writing CGI reply";
					break;
			}
			if (FCGI_fputc((int)*p, ffp) == EOF) {
				return "writing CGI reply";
			}
next_char:
			p++;
		}
out_of_loop:
		if (p < buf + nread) {
			/* It is not clear if a cast from ptrdiff_t to size_t
			 * is valid. It would be better to use an index into
			 * buf instead of p.
			 */
			const size_t write_size = (size_t)(buf + nread - p);
			/* Currently ignored */
			bool error = true;
			if (fcgi_fwrite(p, 1, write_size, ffp, &error) != write_size) {
				return "writing CGI reply";
			}
		}
	} else {
		if (nread < 0) {
			return "reading CGI reply";
		}
		(void)close(*fdp);
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
		(void)close(*fdp);
		*fdp = -1;
	}
	return NULL;
}

static bool fcgi_pass_request(struct fcgi_context *fc)
{
	char buf[FCGI_BUF_SIZE];
	size_t nread;
	/* Currently ignored */
	bool error = true;

	/* eat the whole request and pass it to CGI */
	while ((nread = fcgi_fread(buf, 1, sizeof(buf), FCGI_stdin, &error)) > 0) {
		if (nread == (size_t)EOF) {
			break;
		}
		if (write_all(fc->fd_stdin, buf, nread) <= 0) {
			fcgi_finish(fc, "reading the request");
			return false;
		}
	}
	(void)close(fc->fd_stdin);
	fc->fd_stdin = -1;

	return true;
}

static void fcgi_pass(struct fcgi_context *fc)
{
	char buf[FCGI_BUF_SIZE];
	fd_set rset;
	int maxfd = 1 + max_va(fc->fd_stdout, fc->fd_stderr, MAX_VA_SENTINEL);
	int nready;
	const char *err;

	if (!fcgi_pass_request(fc))
		return;

	/* now pass CGI reply back */
	while (fc->fd_stdout >= 0 || fc->fd_stderr >= 0) {
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
			if (err != NULL) {
				fcgi_finish(fc, err);
				return;
			}
		}
		if (fc->fd_stderr >= 0 && FD_ISSET(fc->fd_stderr, &rset)) {
			if (stderr_to_fastcgi)
				err = fcgi_pass_fd(fc, &fc->fd_stderr, FCGI_stderr, buf, sizeof(buf));
			else
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

static int check_file_perms(const char *path)
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

static char *get_cgi_filename(void) /* and fixup environment */
{
	size_t buflen = 1, docrootlen;
	char *buf = NULL;
	char *docroot, *scriptname, *p;

	size_t rf_len;
	char *pathinfo = NULL;

	if ((p = getenv("SCRIPT_FILENAME")) != NULL) {
		if (check_file_perms(p) != 0)
			goto err;
		return strdup(p);
	}

	if ((p = getenv("DOCUMENT_ROOT")) != NULL) {
		docroot = p;
		docrootlen = strlen(p);
		buflen += docrootlen;
	} else {
		goto err;
	}

	if ((p = getenv("SCRIPT_NAME")) != NULL) {
		buflen += strlen(p);
		scriptname = p;
	} else {
		goto err;
	}

	buf = malloc(buflen);
	if (buf == NULL) goto err;

	strcpy(buf, docroot);
	strcpy(buf + docrootlen, scriptname);
	pathinfo = strdup(buf);
	if (pathinfo == NULL) {
		goto err;
	}

	while(true) {
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
				if (p == NULL) goto err;
				*p = '\0';
		}
	}

err:
	free(pathinfo);
	free(buf);
	return NULL;
}

static int blacklisted_env(const char *var_name, const char *var_name_end)
{
	size_t i;

	if (var_name_end - var_name > 4 && strncmp(var_name, "HTTP", 4) == 0) {
		/* HTTP_*, HTTPS */
		return 1;
	}

	for (i = 0; i < LENGTH(blacklisted_env_vars); i++) {
		if (strcmp(var_name, blacklisted_env_vars[i]) == 0) {
			return 1;
		}
	}

	return 0;
}

static void inherit_environment(void)
{
	char * const * p;
	char *q;

	for (p = inherited_environ; *p; p++) {
		q = strchr(*p, '=');
		if (q == NULL) {
			(void)fprintf(stderr, "Suspect value in environment: %s\n", *p);
			continue;
		}
		*q = '\0';

		if (getenv(*p) == NULL && blacklisted_env(*p, q) == 0) {
			*q = '=';
			putenv(*p);
		}

		*q = '=';
	}
}

static bool is_allowed_program(const char *program) {
	size_t i;
	if (allowed_programs_count == 0)
		return true;

	for (i = 0; i < allowed_programs_count; i++) {
		if (strcmp(allowed_programs[i], program) == 0)
			return true;
	}

	return false;
}

static void cgi_error(const char *message, const char *reason, const char *filename)
{
	(void)printf("Status: %s\r\nContent-Type: text/plain\r\n\r\n%s\r\n",
		message, message);
	(void)fflush(stdout);
	if (filename != NULL) {
		(void)fprintf(stderr, "%s (%s)\n", reason, filename);
	} else {
		(void)fputs(reason, stderr);
		(void)fputc((int)'\n', stderr);
	}
	_exit(99);
}

static void handle_fcgi_request(void)
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
			(void)close(pipe_in[1]);
			(void)close(pipe_out[0]);
			(void)close(pipe_err[0]);

			(void)dup2(pipe_in[0], 0);
			(void)dup2(pipe_out[1], 1);
			(void)dup2(pipe_err[1], 2);

			(void)close(pipe_in[0]);
			(void)close(pipe_out[1]);
			(void)close(pipe_err[1]);

			(void)close(FCGI_fileno(FCGI_stdout));

			(void)signal(SIGCHLD, SIG_DFL);
			(void)signal(SIGPIPE, SIG_DFL);

			filename = get_cgi_filename();
			inherit_environment();
			if (filename == NULL)
				cgi_error("403 Forbidden", "Cannot get script name, are DOCUMENT_ROOT and SCRIPT_NAME (or SCRIPT_FILENAME) set and is the script executable?", NULL);

			if (!is_allowed_program(filename))
				cgi_error("403 Forbidden", "The given script is not allowed to execute", filename);

			last_slash = strrchr(filename, '/');
			if (last_slash == NULL)
				cgi_error("403 Forbidden", "Script name must be a fully qualified path", filename);

			*last_slash = '\0';
			if (chdir(filename) < 0)
				cgi_error("403 Forbidden", "Cannot chdir to script directory", filename);

			*last_slash = '/';

			(void)execl(filename, filename, (void *)NULL);
			cgi_error("502 Bad Gateway", "Cannot execute script", filename);

		default: /* parent */
			(void)close(pipe_in[0]);
			(void)close(pipe_out[1]);
			(void)close(pipe_err[1]);

			fc.fd_stdin = pipe_in[1];
			fc.fd_stdout = pipe_out[0];
			fc.fd_stderr = pipe_err[0];
			fc.reply_state = REPLY_STATE_INIT;
			fc.cgi_pid = pid;

			fcgi_pass(&fc);
	}
	return;

err_fork:
	(void)close(pipe_err[0]);
	(void)close(pipe_err[1]);

err_pipeerr:
	(void)close(pipe_out[0]);
	(void)close(pipe_out[1]);

err_pipeout:
	(void)close(pipe_in[0]);
	(void)close(pipe_in[1]);

err_pipein:

	(void)FCGI_puts("Status: 502 Bad Gateway\nContent-type: text/plain\n");
	(void)FCGI_puts("System error");
}

static void fcgiwrap_main(void)
{
	(void)signal(SIGCHLD, SIG_IGN);
	(void)signal(SIGPIPE, SIG_IGN);

	inherited_environ = environ;

	while (FCGI_Accept() >= 0) {
		handle_fcgi_request();
	}
}

static volatile sig_atomic_t nrunning;

static void sigchld_handler(int dummy)
{
	int status;

	while ((dummy = waitpid(-1, &status, WNOHANG)) > 0) {
		/* sanity check */
		if (nrunning > 0)
			nrunning--;

		/* we _should_ print something about the exit code
		 * but the sighandler context is _very_ bad for this
		 */
	}
}

static void prefork(int nchildren)
{
	bool startup = true;

	if (nchildren == 1) {
		return;
	}

	(void)signal(SIGCHLD, sigchld_handler);

	while (true) {
		while (nrunning < nchildren) {
			pid_t pid = fork();
			if (pid == 0) {
				return;
			} else if (pid != -1) {
				nrunning++;
			} else {
				if (startup) {
					(void)fprintf(stderr, "Failed to prefork: %s\n", strerror(errno));
					exit(1);
				} else {
					(void)fprintf(stderr, "Failed to fork: %s\n", strerror(errno));
					break;
				}
			}
		}
		startup = false;
		(void)pause();
	}
}

static int listen_on_fd(int fd) {
	int one = 1;

	if (listen(fd, 511) < 0) {
		perror("Failed to listen");
		return -1;
	}
	/* If the maximum value of socklen_t exceeds SIZE_MAX, casting size_t
	 * to socklen_t is not safe.
	 */
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, (socklen_t)sizeof one) < 0) {
		perror("Failed to enable SO_REUSEADDR");
		return -1;
	}
	if (dup2(fd, 0) < 0) {
		perror("Failed to move socket to fd 0");
		return -1;
	}
	if (close(fd) < 0) {
		perror("Failed to close original socket");
		return -1;
	}

	return 0;
}

static int setup_socket(char *url) {
	char *p = url;
	char *q;
	int fd;
	int port;
	size_t sockaddr_size;

	union {
		struct sockaddr sa;
		struct sockaddr_un sa_un;
		struct sockaddr_in sa_in;
		struct sockaddr_in6 sa_in6;
	} sa;

	if (strncmp(p, "unix:", sizeof("unix:") - 1) == 0) {
		p += sizeof("unix:") - 1;

		if (strlen(p) >= UNIX_PATH_MAX) {
			(void)fprintf(stderr, "Socket path too long, exceeds %d characters\n",
			        UNIX_PATH_MAX);
			return -1;
		}

		sockaddr_size = sizeof sa.sa_un;
		sa.sa_un.sun_family = AF_UNIX;
		strcpy(sa.sa_un.sun_path, p);
	} else if (strncmp(p, "tcp:", sizeof("tcp:") - 1) == 0) {
		p += sizeof("tcp:") - 1;

		q = strchr(p, ':');
		if (q == NULL) {
			goto invalid_url;
		}
		port = atoi(q+1);
		if (port <= 0 || port > 65535) {
			goto invalid_url;
		}
		sockaddr_size = sizeof sa.sa_in;
		sa.sa_in.sin_family = AF_INET;
		sa.sa_in.sin_port = htons(port);
		*q = 0;
		if (inet_pton(AF_INET, p, &sa.sa_in.sin_addr) < 1) {
			goto invalid_url;
		}
	} else if (strncmp(p, "tcp6:[", sizeof("tcp6:[") - 1) == 0) {
		p += sizeof("tcp6:[") - 1;
		q = strchr(p, ']');
		if (q == NULL || q[0] == '\0' || q[1] != ':') {
			goto invalid_url;
		}
		port = atoi(q+2);
		if (port <= 0 || port > 65535) {
			goto invalid_url;
		}
		sockaddr_size = sizeof sa.sa_in6;
		sa.sa_in6.sin6_family = AF_INET6;
		sa.sa_in6.sin6_port = htons(port);
		*q = 0;
		if (inet_pton(AF_INET6, p, &sa.sa_in6.sin6_addr) < 1) {
			goto invalid_url;
		}
	} else {
invalid_url:
		(void)fprintf(stderr, "Valid socket URLs are:\n"
		                "unix:/path/to/socket for Unix sockets\n"
		                "tcp:dot.ted.qu.ad:port for IPv4 sockets\n"
		                "tcp6:[ipv6_addr]:port for IPv6 sockets\n");
		return -1;
	}

	fd = socket(sa.sa.sa_family, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("Failed to create socket");
		return -1;
	}
	/* If the maximum value of socklen_t exceeds SIZE_MAX, casting size_t
	 * to socklen_t is not safe.
	 */
	if (bind(fd, &sa.sa, sockaddr_size) < 0) {
		perror("Failed to bind");
		return -1;
	}

	return listen_on_fd(fd);
}

int main(int argc, char **argv)
{
	int nchildren = 1;
	char *socket_url = NULL;
	int c;

	while ((c = getopt(argc, argv, "c:hfs:p:")) != -1) {
		switch (c) {
			case 'f':
				stderr_to_fastcgi = true;
				break;
			case 'h':
				(void)printf("Usage: %s [OPTION]\nInvokes CGI scripts as FCGI.\n\n"
					PACKAGE_NAME" version "PACKAGE_VERSION"\n\n"
					"Options are:\n"
					"  -f\t\t\tSend CGI's stderr over FastCGI\n"
					"  -c <number>\t\tNumber of processes to prefork\n"
					"  -s <socket_url>\tSocket to bind to (say -s help for help)\n"
					"  -h\t\t\tShow this help message and exit\n"
					"  -p <path>\t\tRestrict execution to this script. (repeated options will be merged)\n"
					"\nReport bugs to Grzegorz Nosek <"PACKAGE_BUGREPORT">.\n"
					PACKAGE_NAME" home page: <http://nginx.localdomain.pl/wiki/FcgiWrap>\n",
					argv[0]
				);
				return 0;
			case 'c':
				nchildren = atoi(optarg);
				break;
			case 's':
				socket_url = strdup(optarg);
				break;
			case 'p':
				allowed_programs = realloc(allowed_programs, (allowed_programs_count + 1) * sizeof (char *));
				if (allowed_programs == NULL)
					abort();
				allowed_programs[allowed_programs_count++] = strdup(optarg);
				break;
			case '?':
				if (optopt == 'c' || optopt == 's' || optopt == 'p')
					(void)fprintf(stderr, "Option -%c requires an argument.\n", optopt);
				else if (isprint(optopt))
					(void)fprintf(stderr, "Unknown option `-%c'.\n", optopt);
				else
					(void)fprintf(stderr,
						"Unknown option character `\\x%x'.\n",
						optopt);
				return 1;
			default:
				abort();
		}
	}

#ifdef HAVE_SYSTEMD
	if (sd_listen_fds(true) > 0) {
		/* systemd woke us up. we should never see more than one FD passed to us. */
		if (listen_on_fd(SD_LISTEN_FDS_START) < 0) {
			return 1;
		}
	} else
#endif
	if (socket_url) {
		if (setup_socket(socket_url) < 0) {
			return 1;
		}
		free(socket_url);
	}

	prefork(nchildren);
	fcgiwrap_main();
	return 0;
}

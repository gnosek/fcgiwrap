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
#include <time.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>

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

extern char **environ;
static char * const * inherited_environ;
static const char **allowed_programs;
static size_t allowed_programs_count;

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

static int stderr_to_fastcgi = 0;
static int use_suexec = 0;
static FILE* suexec_log;


#define FCGI_BUF_SIZE 4096
#define MIN_ID_ALLOWED 1000

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

static bool fcgi_pass_request(struct fcgi_context *fc)
{
	char buf[FCGI_BUF_SIZE];
	ssize_t nread;

	/* eat the whole request and pass it to CGI */
	while ((nread = FCGI_fread(buf, 1, sizeof(buf), FCGI_stdin)) > 0) {
		if (write_all(fc->fd_stdin, buf, nread) <= 0) {
			fcgi_finish(fc, "reading the request");
			return false;
		}
	}
	close(fc->fd_stdin);
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
			if (err) {
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

static void print_time_suexec_log(void)
{
	time_t rawtime;
	struct tm* info;
	char* months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
	time(&rawtime);
	info = localtime(&rawtime);
	fprintf(suexec_log, "[%d/%s/%d %d:%d:%d]: ", (info->tm_year+1900), months[info->tm_mon], info->tm_mday, info->tm_hour, info->tm_min, info->tm_sec);
}

static int check_suexec(const char* const cgi_filename, struct stat *ls)
{
	struct stat pls;
	struct passwd *user;
	struct group *group;
	char* p;
	size_t len_docroot, len_filename, len_userdir;

	/* Can stat the target cgi program */
	if (lstat(cgi_filename, ls) < 0) {
		print_time_suexec_log();
		fprintf(suexec_log, "Can't stat %s\n", cgi_filename);
		fflush(suexec_log);
		return -EACCES;
	} else if (!S_ISREG(ls->st_mode) && S_ISLNK(ls->st_mode)) {
		if (stat(cgi_filename, ls) < 0) {
			print_time_suexec_log();
			fprintf(suexec_log, "Can't stat %s\n", cgi_filename);
			fflush(suexec_log);
			return -EACCES;
		}
	}

	/* Is the target cgi program not writable by anyone else */
	/* Is the target cgi program NOT setuid or setgid */
	if ((ls->st_mode & S_IWOTH) ||
		(ls->st_mode & S_ISUID) ||
		(ls->st_mode & S_ISGID)) {
		print_time_suexec_log();
		fprintf(suexec_log, "%s is writable by anyone or has setuid/setgid set\n", cgi_filename);
		fflush(suexec_log);
		return -EACCES;
	}

	/* Is the target userid or groupid a superuser */
	if (ls->st_uid == 0 || ls->st_gid == 0) {
		print_time_suexec_log();
		fprintf(suexec_log, "%s is owned by root\n", cgi_filename);
		fflush(suexec_log);
		return -EACCES;
	}

	/* Is the target user name valid */
	user = getpwuid(ls->st_uid);
	if (user == NULL) {
		print_time_suexec_log();
		fprintf(suexec_log, "%s is owned by user id %d. %d is not a user on this system\n", cgi_filename, ls->st_uid, ls->st_uid);
		fflush(suexec_log);
		return -EACCES;
	}

	/* Is the target group name valid */
	group = getgrgid(ls->st_gid);
	if (group == NULL) {
		print_time_suexec_log();
		fprintf(suexec_log, "%s is owned by group id %d. %d is not a group on this system\n", cgi_filename, ls->st_gid, ls->st_gid);
		fflush(suexec_log);
		return -EACCES;
	}

	/* Is the target user/group the same as the owner */
	if (group->gr_gid != user->pw_gid) {
		print_time_suexec_log();
		fprintf(suexec_log, "%s is owned by group id %d but expected %d\n", cgi_filename, group->gr_gid, user->pw_gid);
		fflush(suexec_log);
		return -EACCES;
	}

	/* Is the target groupid or userid above the minimum ID number */
	if (group->gr_gid < MIN_ID_ALLOWED || user->pw_uid < MIN_ID_ALLOWED) {
		print_time_suexec_log();
		fprintf(suexec_log, "%s is owned by user id %d. The minimal group/user id allowed is %d\n", cgi_filename, ls->st_uid, MIN_ID_ALLOWED);
		fflush(suexec_log);
		return -EACCES;
	}

	/* Is the directory within document root */
	if ((p = getenv("DOCUMENT_ROOT"))) {
		len_docroot = strlen(p);
		len_filename = strlen(cgi_filename);
		len_userdir = strlen(user->pw_dir);

		if (len_docroot > len_filename) {
			print_time_suexec_log();
			fprintf(suexec_log, "%s is not located in %s\n", cgi_filename, p);
			fflush(suexec_log);
			return -EACCES;
		} else if (strncmp(p, cgi_filename, len_docroot) != 0) {
			print_time_suexec_log();
			fprintf(suexec_log, "%s is not located in %s\n", cgi_filename, p);
			fflush(suexec_log);
			return -EACCES;
		} else if (len_userdir > len_filename) { /* Is the target directory within the user's directory */
			print_time_suexec_log();
			fprintf(suexec_log, "%s is not located in the user's directory\n", cgi_filename);
			fflush(suexec_log);
			return -EACCES;
		} else if (strncmp(user->pw_dir, cgi_filename, len_userdir) != 0) {
			print_time_suexec_log();
			fprintf(suexec_log, "%s is not located in the user's directory\n", cgi_filename);
			fflush(suexec_log);
			return -EACCES;
		}
	} else {
		/* DOCUMENT_ROOT must be set to use suexec */
		print_time_suexec_log();
		fprintf(suexec_log, "DOCUMENT_ROOT is not set. DOCUMENT_ROOT must be set to use suexec for %s\n", cgi_filename);
		fflush(suexec_log);
		return -EACCES;
	}

	p = strrchr(cgi_filename, '/');

	if (!p) {
		print_time_suexec_log();
		fprintf(suexec_log, "Unable to / in %s\n", cgi_filename);
		fflush(suexec_log);
		return -EACCES;
	}

    *p = 0;
	if (lstat(cgi_filename, &pls) < 0) {
		print_time_suexec_log();
		fprintf(suexec_log, "Unable to stat %s\n", cgi_filename);
		fflush(suexec_log);
		goto err_parent;
	} else if (!S_ISDIR(pls.st_mode) && S_ISLNK(pls.st_mode)) {
		if (stat(cgi_filename, &pls) < 0) {
			print_time_suexec_log();
			fprintf(suexec_log, "Unable to stat %s\n", cgi_filename);
			fflush(suexec_log);
			goto err_parent;
		} else if (!S_ISDIR(pls.st_mode)) {
			print_time_suexec_log();
			fprintf(suexec_log, "%s is not a directory\n", cgi_filename);
			fflush(suexec_log);
			goto err_parent;
		}
	}
	/* Make sure directory is not writable by anyone else */
	if (pls.st_mode & S_IWOTH) {
		print_time_suexec_log();
		fprintf(suexec_log, "Parent directory %s is writable by anyone.", cgi_filename);
        *p = '/';
        fprintf(suexec_log, " Don't execute %s\n", cgi_filename);
        *p = 0;
		fflush(suexec_log);
		goto err_parent;
	}
	if (pls.st_gid != ls->st_gid || pls.st_uid != ls->st_uid) {
		print_time_suexec_log();
		fprintf(suexec_log, "%s is owned by user %d group %d. Expected user owner %d group owner %d\n", cgi_filename, pls.st_uid, pls.st_gid, ls->st_uid, ls->st_gid);
		fflush(suexec_log);
		goto err_parent;
	}
    *p = '/';

	return 0;
err_parent:
    *p = '/';
	return -EACCES;
}

static char *get_cgi_filename(void) /* and fixup environment */
{
	int buflen = 1, docrootlen;
	char *buf = NULL;
	char *docroot, *scriptname, *p;

	int rf_len;
	char *pathinfo = NULL;

	if ((p = getenv("SCRIPT_FILENAME"))) {
		if (check_file_perms(p) != 0)
			goto err;
		return strdup(p);
	}

	if ((p = getenv("DOCUMENT_ROOT"))) {
		docroot = p;
		docrootlen = strlen(p);
		buflen += docrootlen;
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

static void inherit_environment(void)
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

static bool is_allowed_program(const char *program) {
	size_t i;
	if (!allowed_programs_count)
		return true;

	for (i = 0; i < allowed_programs_count; i++) {
		if (!strcmp(allowed_programs[i], program))
			return true;
	}

	return false;
}

static void cgi_error(const char *message, const char *reason, const char *filename)
{
	printf("Status: %s\r\nContent-Type: text/plain\r\n\r\n%s\r\n",
		message, message);
	fflush(stdout);
	if (filename) {
		fprintf(stderr, "%s (%s)\n", reason, filename);
	} else {
		fputs(reason, stderr);
		fputc('\n', stderr);
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
	char *p;
	pid_t pid;
	struct stat ls;
	struct group *group;
	struct passwd *user;

	struct fcgi_context fc;

	if (pipe(pipe_in) < 0) goto err_pipein;
	if (pipe(pipe_out) < 0) goto err_pipeout;
	if (pipe(pipe_err) < 0) goto err_pipeerr;

	switch((pid = fork())) {
		case -1:
			goto err_fork;

		case 0: /* child */
			close(pipe_in[1]);
			close(pipe_out[0]);
			close(pipe_err[0]);

			dup2(pipe_in[0], 0);
			dup2(pipe_out[1], 1);
			dup2(pipe_err[1], 2);

			close(pipe_in[0]);
			close(pipe_out[1]);
			close(pipe_err[1]);

			close(FCGI_fileno(FCGI_stdout));

			signal(SIGCHLD, SIG_DFL);
			signal(SIGPIPE, SIG_DFL);

			filename = get_cgi_filename();
			inherit_environment();
			if (!filename)
				cgi_error("403 Forbidden", "Cannot get script name, are DOCUMENT_ROOT and SCRIPT_NAME (or SCRIPT_FILENAME) set and is the script executable?", NULL);

			if (!is_allowed_program(filename))
				cgi_error("403 Forbidden", "The given script is not allowed to execute", filename);

			p = getenv("FCGI_CHDIR");
			if (p == NULL) {
				last_slash = strrchr(filename, '/');
				if (!last_slash)
					cgi_error("403 Forbidden", "Script name must be a fully qualified path", filename);

				*last_slash = 0;
				if (chdir(filename) < 0)
					cgi_error("403 Forbidden", "Cannot chdir to script directory", filename);

				*last_slash = '/';
			} else if (strcmp(p, "-") != 0) {
				if (chdir(p) < 0) {
					cgi_error("403 Forbidden", "Cannot chdir to FCGI_CHDIR directory", p);
				}
			}

			if (use_suexec) {
				if (check_suexec(filename, &ls) < 0) {
					cgi_error("403 Forbidden", "Cannot suexec script because the permissions are incorrect", filename);
				}
				if (setgid(ls.st_gid) < 0) {
					print_time_suexec_log();
					fprintf(suexec_log, "Cannot change process to script group owner %d to execute %s\n", ls.st_gid, filename);
					fflush(suexec_log);
					cgi_error("403 Forbidden", "Cannot change to script group owner", filename);
				}
				if (setuid(ls.st_uid) < 0) {
					print_time_suexec_log();
					fprintf(suexec_log, "Cannot change process to script user owner %d to execute %s\n", ls.st_uid, filename);
					fflush(suexec_log);
					cgi_error("403 Forbidden", "Cannot change to script user owner", filename);
				}
				print_time_suexec_log();
				group = getgrgid(ls.st_gid);
				user = getpwuid(ls.st_uid);
				fprintf(suexec_log, "uid: (%d/%s) gid: (%d/%s) cmd: %s\n", ls.st_uid, user->pw_name, ls.st_gid, group->gr_name, filename);
				fflush(suexec_log);
			}

			execl(filename, filename, (void *)NULL);
			cgi_error("502 Bad Gateway", "Cannot execute script", filename);

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

static volatile sig_atomic_t sigint_received ;
static void sigint_handler(int __attribute__((__unused__))dummy)
{
	sigint_received = 1;
	FCGX_ShutdownPending(); // Or we could send SIGUSR1
}

static void fcgiwrap_main(void)
{
	struct sigaction a;
	signal(SIGCHLD, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);

	// Use sigaction for SIGINT so we can avoid SA_RESTART and actually react
	a.sa_handler = sigint_handler;
	a.sa_flags = 0;
	sigemptyset( &a.sa_mask );
	sigaction( SIGINT, &a, NULL );
	sigaction( SIGTERM, &a, NULL );

	inherited_environ = environ;

	while (FCGI_Accept() >= 0 && !sigint_received) {
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
	int startup = 1;

	if (nchildren == 1) {
		return;
	}

	signal(SIGCHLD, sigchld_handler);

	while (1) {
		while (nrunning < nchildren) {
			pid_t pid = fork();
			if (pid == 0) {
				return;
			} else if (pid != -1) {
				nrunning++;
			} else {
				if (startup) {
					fprintf(stderr, "Failed to prefork: %s\n", strerror(errno));
					exit(1);
				} else {
					fprintf(stderr, "Failed to fork: %s\n", strerror(errno));
					break;
				}
			}
		}
		startup = 0;
		pause();
	}
}

static int listen_on_fd(int fd) {
	int one = 1;

	if (listen(fd, 511) < 0) {
		perror("Failed to listen");
		return -1;
	}
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) < 0) {
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

	if (!strncmp(p, "unix:", sizeof("unix:") - 1)) {
		p += sizeof("unix:") - 1;

		if (strlen(p) >= UNIX_PATH_MAX) {
			fprintf(stderr, "Socket path too long, exceeds %d characters\n",
					UNIX_PATH_MAX);
			return -1;
		}

		sockaddr_size = sizeof sa.sa_un;
		sa.sa_un.sun_family = AF_UNIX;
		strcpy(sa.sa_un.sun_path, p);
	} else if (!strncmp(p, "tcp:", sizeof("tcp:") - 1)) {
		p += sizeof("tcp:") - 1;

		q = strchr(p, ':');
		if (!q) {
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
	} else if (!strncmp(p, "tcp6:[", sizeof("tcp6:[") - 1)) {
		p += sizeof("tcp6:[") - 1;
		q = strchr(p, ']');
		if (!q || !q[0] || q[1] != ':') {
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
		fprintf(stderr, "Valid socket URLs are:\n"
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
	if (bind(fd, &sa.sa, sockaddr_size) < 0) {
		perror("Failed to bind");
		return -1;
	}

	if (listen_on_fd(fd) < 0) {
		return -1;
	}

	return fd;
}

int main(int argc, char **argv)
{
	int nchildren = 1;
	char *socket_url = NULL;
	int i_am_root = (getuid() == 0);
	int fd = 0;
	int c;

	while ((c = getopt(argc, argv, "c:hufs:p:")) != -1) {
		switch (c) {
			case 'f':
				stderr_to_fastcgi++;
				break;
			case 'h':
				printf("Usage: %s [OPTION]\nInvokes CGI scripts as FCGI.\n\n"
					PACKAGE_NAME" version "PACKAGE_VERSION"\n\n"
					"Options are:\n"
					"  -f\t\t\tSend CGI's stderr over FastCGI\n"
					"  -c <number>\t\tNumber of processes to prefork\n"
					"  -u <use_suexec>\tUse suexec like behavior. Change to owner uid and gid before executing. (See https://httpd.apache.org/docs/2.4/suexec.html)\n"
					"  -s <socket_url>\tSocket to bind to (say -s help for help)\n"
					"  -h\t\t\tShow this help message and exit\n"
					"  -p <path>\t\tRestrict execution to this script. (repeated options will be merged)\n"
					"\nReport bugs to Grzegorz Nosek <"PACKAGE_BUGREPORT">.\n"
					PACKAGE_NAME" home page: <http://nginx.localdomain.pl/wiki/FcgiWrap>\n",
					argv[0]
				);
				return 0;
			case 'u':
				if (!i_am_root) {
					fprintf(stderr, "Option -%c requires program to be run as superuser.\n", optopt);
					return 1;
				}
				use_suexec = 1;
				break;
			case 'c':
				nchildren = atoi(optarg);
				break;
			case 's':
				socket_url = strdup(optarg);
				break;
			case 'p':
				allowed_programs = realloc(allowed_programs, (allowed_programs_count + 1) * sizeof (char *));
				if (!allowed_programs)
					abort();
				allowed_programs[allowed_programs_count++] = strdup(optarg);
				break;
			case '?':
				if (optopt == 'c' || optopt == 's' || optopt == 'p')
					fprintf(stderr, "Option -%c requires an argument.\n", optopt);
				else if (isprint(optopt))
					fprintf(stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf(stderr,
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
		fd = setup_socket(socket_url);
		if (fd < 0) {
			return 1;
		}
	}

	if (use_suexec) {
		suexec_log = fopen("/var/log/fcgiwrap_suexec.log", "ab");
		if (suexec_log == NULL) {
			fprintf(stderr, "An error occurred while opening /var/log/fcgiwrap_suexec.log '%s'", strerror(errno));
			return 1;
		}
	}

	prefork(nchildren);
	fcgiwrap_main();

	if (fd) {
		const char *p = socket_url;
		close(fd);

		if (socket_url) {
			if (!strncmp(p, "unix:", sizeof("unix:") - 1)) {
				p += sizeof("unix:") - 1;
				unlink(p);
			}
		}
	}
	if (suexec_log) {
		fclose(suexec_log);
	}
	return 0;
}

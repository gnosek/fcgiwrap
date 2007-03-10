#include <fcgi_stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/select.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>

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

static void fcgi_pass(int fd_stdin, int fd_stdout, int fd_stderr)
{
	char buf[FCGI_BUF_SIZE];
	size_t nread;
	fd_set rset;
	int maxfd = (fd_stdout > fd_stderr) ? fd_stdout : fd_stderr;
	int nready;

	/* slurp the whole input and pass it to CGI */

	while ((nread = fread(buf, 1, sizeof(buf), stdin))) {
		if (write_all(fd_stdin, buf, nread) <= 0) return;
	}

	close(fd_stdin);

	/* now wait for CGI replies on stdout and stderr */

	while (fd_stdout >= 0 && fd_stderr >= 0) {
		FD_ZERO(&rset);
		if (fd_stdout >= 0) FD_SET(fd_stdout, &rset);
		if (fd_stderr >= 0) FD_SET(fd_stderr, &rset);
		nready = select(maxfd, &rset, NULL, NULL, NULL);
		if (nready < 0) {
			if (errno == EAGAIN) continue;
			return; /* better error checking needed */
		}
		if (fd_stdout >= 0 && FD_ISSET(fd_stdout, &rset)) {
			nread = read(fd_stdout, buf, sizeof(buf));
			if (nread <= 0) {
				close(fd_stdout);
				fd_stdout = -1;
			}
			fwrite(buf, 1, nread, stdout);
		}
		if (fd_stderr >= 0 && FD_ISSET(fd_stderr, &rset)) {
			nread = read(fd_stderr, buf, sizeof(buf));
			if (nread <= 0) {
				close(fd_stderr);
				fd_stderr = -1;
			}
			fwrite(buf, 1, nread, stderr);
		}
	}
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

char *get_cgi_filename()
{
	int buflen = 1, docrootlen;
	char *buf;
	char *docroot, *scriptname, *p;

	if ((p = getenv("DOCUMENT_ROOT"))) {
		docroot = p;
		buflen += docrootlen = strlen(p);
	} else {
		return NULL;
	}

	if ((p = getenv("SCRIPT_NAME"))) {
		buflen += strlen(p);
		scriptname = p;
	} else {
		return NULL;
	}

	buf = malloc(buflen);
	if (!buf) return NULL;

	strcpy(buf, docroot);
	strcpy(buf + docrootlen, scriptname);

	while(1) {
		switch(check_file_perms(buf)) {
			case -EACCES: return NULL;
			case 0: return buf;
			default:
				p = strrchr(buf, '/');
				if (!p) return NULL;
				*p = 0;
		}
	}

	return NULL;
}

static void handle_fcgi_request()
{
	int pipe_in[2];
	int pipe_out[2];
	int pipe_err[2];
	char *filename;

	/* XXX error handling */
	pipe(pipe_in);
	pipe(pipe_out);
	pipe(pipe_err);

	switch(fork()) {
		case -1:
			return;

		case 0: /* child */
			filename = get_cgi_filename();
			if (!filename) {
				puts("Status: 403 Forbidden\nContent-type: text/plain\n\n403");
				exit(99);
			}
			close(pipe_in[1]);
			close(pipe_out[0]);
			close(pipe_err[0]);

			dup2(pipe_in[0], 0);
			dup2(pipe_out[1], 1);
			dup2(pipe_err[1], 2);

			execl(filename, filename, NULL);
			/* we _do_ want a 502 here probably */
			exit(99);

		default: /* parent */
			close(pipe_in[0]);
			close(pipe_out[1]);
			close(pipe_err[1]);

			fcgi_pass(pipe_in[1], pipe_out[0], pipe_err[0]);
	}
}

int main(int argc, char **argv)
{
	signal(SIGCHLD, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);

	while (FCGI_Accept() >= 0) {
		handle_fcgi_request();
	}

	return 0;
}


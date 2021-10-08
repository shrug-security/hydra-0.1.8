/*
 *  Hydra, an http server
 *  Copyright (C) 1995 Paul Phillips <paulp@go2net.com>
 *  Some changes Copyright (C) 1996 Larry Doolittle <ldoolitt@boa.org>
 *  Some changes Copyright (C) 1999 Jon Nelson <jnelson@boa.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 1, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

/* $Id: log.c,v 1.13 2002/11/29 14:56:36 andreou Exp $ */

#include "boa.h"

extern char *error_log_name;
extern char *access_log_name;
extern char *cgi_log_name;
int cgi_log_fd;

FILE *
fopen_gen_fd(char *spec, const char *mode);

FILE *
fopen_gen_fd(char *spec, const char *mode)
{
	int fd;
	if (!spec || *spec == '\0')
		return NULL;
	if ((fd = open_gen_fd(spec)) == -1)
		return NULL;
	return fdopen(fd, mode);
} /* fopen_gen_fd() */

/*
 * Name: open_logs
 *
 * Description: Opens access log, error log, and if specified, cgi log
 * Ties stderr to error log, except during cgi execution, at which
 * time cgi log is the stderr for cgis.
 *
 * Access log is line buffered, error log is not buffered.
 *
 */

void
open_logs(void)
{
	int access_log;

	/*
	 * if error_log_name is set, dup2 stderr to it
	 * otherwise leave stderr alone
	 * we don't want to tie stderr to /dev/null
	 */
	if (error_log_name) {
		int error_log;
		
		/* open the log file */
		if (!(error_log = open_gen_fd(error_log_name))) {
			DIE("unable to open error log");
		}

		/* redirect stderr to error_log */
		if (dup2(error_log, STDERR_FILENO) == -1) {
			DIE("unable to dup2 the error log");
		}
		close(error_log);
	}

	/* set the close-on-exec to true */
	if (access_log_name) {
		access_log = open_gen_fd(access_log_name);
	} else {
		access_log = open("/dev/null", 0);
	}

	if (access_log < 0) {
		DIE("unable to open access log");
	}
	if (dup2(access_log, STDOUT_FILENO) == -1) {
		DIE("can't dup2 /dev/null to STDOUT_FILENO");
	}
	close(access_log);

	if (cgi_log_name) {
		cgi_log_fd = open_gen_fd(cgi_log_name);
		if (cgi_log_fd == -1) {
			WARN("open cgi_log");
			free(cgi_log_name);
			cgi_log_name = NULL;
			cgi_log_fd = -1;
		} else {
			if (set_cloexec_fd(cgi_log_fd) == -1) {
				WARN("unable to set close-on-exec flag for cgi_log");
				free(cgi_log_name);
				cgi_log_name = NULL;
				close(cgi_log_fd);
				cgi_log_fd = -1;
			}
		}
	}

#ifdef SETVBUF_REVERSED
	setvbuf(stderr, _IONBF, (char *) NULL, 0);
	setvbuf(stdout, _IOLBF, (char *) NULL, 0);
#else
	setvbuf(stderr, (char *) NULL, _IONBF, 0);
	setvbuf(stdout, (char *) NULL, _IOLBF, 0);
#endif

} /* open_logs() */

/*
 * Name: log_access
 *
 * Description: Writes log data to access_log.
 */

/* NOTES on the commonlog format:
 * Taken from notes on the NetBuddy program
 *  http://www.computer-dynamics.com/commonlog.html
 *
 * remotehost
 *
 * remotehost rfc931 authuser [date] "request" status bytes
 *
 * remotehost - IP of the client
 * rfc931 - remote name of the user (always '-')
 * authuser - username entered for authentication - almost always '-'
 * [date] - the date in [08/Nov/1997:01:05:03 -0600] (with brackets) format
 * "request" - literal request from the client (boa may clean this up,
 *   replacing control-characters with '_' perhaps - NOTE: not done)
 * status - http status code
 * bytes - number of bytes transferred
 *
 * boa appends:
 *   referer
 *   user-agent
 *
 * and may prepend (depending on configuration):
 * virtualhost - the name or IP (depending on whether name-based
 *   virtualhosting is enabled) of the host the client accessed
 */

void
log_access(request *req)
{
	char buf[30];

	if (!access_log_name)
		return;
	
	if (req->hostname && req->hostname[0]!=0) {
		printf("%s ", req->hostname);
	} else {
		printf( "unknown ");
	}

	get_commonlog_time(buf);
#ifndef USE_LONG_OFFSETS
	printf("%s - - %s\"%s\" %d %ld \"%s\" \"%s\"\n",
#else
	printf("%s - - %s\"%s\" %d %lld \"%s\" \"%s\"\n",
#endif
	       req->remote_ip_addr,
	       buf,
	       req->logline,
	       req->response_status,
	       req->filepos,
	       (req->header_referer ? req->header_referer : "-"),
	       (req->header_user_agent ? req->header_user_agent : "-"));
} /* log_access() */

/*
 * Name: log_error_doc
 *
 * Description: Logs the current time and transaction identification
 * to the stderr (the error log):
 * should always be followed by an fprintf to stderr
 *
 * This function used to be implemented with a big fprintf, but not
 * all fprintf's are reliable in the face of null string pointers
 * (SunOS, in particular).  As long as I had to add the checks for
 * null pointers, I changed from fprintf to fputs.
 *
 * Example output:
 * www.testserver.com [08/Nov/1997:01:05:03 -0600] request 192.228.331.232 "GET /~joeblow/dir/ HTTP/1.0" ("/usr/user1/joeblow/public_html/dir/"): write: Broken pipe
 *
 * Apache uses:
 * [Wed Oct 11 14:32:52 2000] [error] [client 127.0.0.1] client denied by server configuration: /export/home/live/ap/htdocs/test
 */

void
log_error_doc(request *req)
{
	int errno_save = errno; /* it's a push-pop thingie; we don't want to alter errno. */
	char buf[30];

	if (req->hostname && req->hostname[0]!=0) {
		fprintf(stderr, "%s ", req->hostname);
	} else {
		fprintf(stderr, "unknown ");
	}

	get_commonlog_time(buf);
	fprintf(stderr, "%s - - %srequest \"%s\" (\"%s\"): ",
		req->remote_ip_addr,
		buf,
		(req->logline != NULL ? req->logline : ""),
		(req->pathname != NULL ? req->pathname : ""));
	errno = errno_save;
} /* log_error_doc() */

/*
 * Name: boa_perror
 *
 * Description: logs an error to user and error file both
 *
 */
void boa_perror(request * req, char *message)
{
	log_error_doc(req);
	perror(message); /* don't need to save errno because log_error_doc does */
	send_r_error(req);
}

/*
 * Name: log_error_time
 *
 * Description: Logs the current time to the stderr (the error log):
 * should always be followed by an fprintf to stderr
 */

void
log_error_time()
{
	int errno_save = errno;
	char buf[30];

	get_commonlog_time(buf);
	fputs(buf, stderr);
	errno = errno_save;
} /* log_error_time() */

/*
 * Name: log_error_mesg
 *
 * Description: performs a log_error_time, writes the file and lineno
 * to stderr (saving errno), and then a perror with message
 *
 */

void
log_error_mesg(char *file, int line, char *mesg)
{
	int errno_save = errno;
	char buf[30];
    
	get_commonlog_time( buf);
	fprintf(stderr, "%s%s:%d - ", buf, file, line);
	errno = errno_save;
	perror(mesg);
	errno = errno_save;
} /* log_error_mesg() */

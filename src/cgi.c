/*
 *  Hydra, an http server
 *  Copyright (C) 1995 Paul Phillips <paulp@go2net.com>
 *  Some changes Copyright (C) 1996,97 Larry Doolittle <ldoolitt@boa.org>
 *  Some changes Copyright (C) 1996 Charles F. Randall <crandall@goldsys.com>
 *  Some changes Copyright (C) 1997-2002 Jon Nelson <jnelson@boa.org>
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

/* $Id: cgi.c,v 1.29 2006-03-09 18:11:07 nmav Exp $ */

#include "boa.h"

static char *env_gen_extra(const char *key, const char *value, int extra);

int verbose_cgi_logs = 0;
/* The +1 is for the the NULL in complete_env */
static char *common_cgi_env[COMMON_CGI_COUNT + 1];

/*
 * Name: create_common_env
 *
 * Description: Set up the environment variables that are common to
 * all CGI scripts
 */

void create_common_env()
{
   int ix = 0, i;


   /* NOTE NOTE NOTE:
      If you (the reader) someday modify this chunk of code to
      handle more "common" CGI environment variables, then bump the
      value COMMON_CGI_COUNT in defines.h UP

      Also, in the case of document_root and server_admin, two variables
      that may or may not be defined depending on the way the server
      is configured, we check for null values and use an empty
      string to denote a NULL value to the environment, as per the
      specification. The quote for which follows:

      "In all cases, a missing environment variable is
      equivalent to a zero-length (NULL) value, and vice versa."
    */
   common_cgi_env[ix++] = env_gen_extra("PATH",
					   ((cgi_path !=
					     NULL) ? cgi_path :
					    DEFAULT_PATH), 0);
   common_cgi_env[ix++] =
       env_gen_extra("SERVER_SOFTWARE", SERVER_NAME "/" SERVER_VERSION, 0);
   common_cgi_env[ix++] =
       env_gen_extra("GATEWAY_INTERFACE", CGI_VERSION, 0);

   /* removed the SERVER_PORT which may change due to SSL support
    * Also removed the DOCUMENT_ROOT, SERVER_NAME, which are now per request.
    */


/* NCSA added */
#ifdef USE_NCSA_CGI_ENV
   common_cgi_env[ix++] = env_gen_extra("SERVER_ROOT", server_root);
#endif

   /* APACHE added */
   common_cgi_env[ix++] =
       env_gen_extra("SERVER_ADMIN", server_admin, 0);
   common_cgi_env[ix] = NULL;

   /* Sanity checking -- make *sure* the memory got allocated */
   if (ix > COMMON_CGI_COUNT) {
      log_error_time();
      fprintf(stderr, "COMMON_CGI_COUNT not high enough.\n");
      exit(1);
   }

   for (i = 0; i < ix; ++i) {
      if (common_cgi_env[i] == NULL) {
	 log_error_time();
	 fprintf(stderr,
		 "Unable to allocate a component of common_cgi_env - out of memory.\n");
	 exit(1);
      }
   }
}

void clear_common_env(void)
{
   int i;

   for (i = 0; i <= COMMON_CGI_COUNT; ++i) {
      if (common_cgi_env[i] != NULL) {
	 free(common_cgi_env[i]);
	 common_cgi_env[i] = NULL;
      }
   }
}

/*
 * Name: env_gen_extra
 *       (and via a not-so-tricky #define, env_gen)
 * This routine calls malloc: please free the memory when you are done
 */
static char *env_gen_extra(const char *key, const char *value, int extra)
{
   char *result;
   int key_len, value_len;

   if (value == NULL)		/* ServerAdmin may not be defined, eg */
      value = "";
   key_len = strlen(key);
   value_len = strlen(value);
   /* leave room for '=' sign and null terminator */
   result = malloc(extra + key_len + value_len + 2);
   if (result) {
      memcpy(result + extra, key, key_len);
      *(result + extra + key_len) = '=';
      memcpy(result + extra + key_len + 1, value, value_len);
      *(result + extra + key_len + value_len + 1) = '\0';
   } else {
      log_error_time();
      perror("malloc");
      log_error_time();
      fprintf(stderr,
	      "tried to allocate (key=value) extra=%d: %s=%s\n",
	      extra, key, value);
   }
   return result;
}

/*
 * Name: add_cgi_env
 *
 * Description: adds a variable to CGI's environment
 * Used for HTTP_ headers
 */

int add_cgi_env(request * req, const char *key, const char *value,
		int http_prefix)
{
   char *p;
   int prefix_len;

   if (http_prefix) {
      prefix_len = 5;
   } else {
      prefix_len = 0;
   }

   if (req->cgi_env_index < CGI_ENV_MAX) {
      p = env_gen_extra(key, value, prefix_len);
      if (!p) {
	 log_error_doc(req);
	 fprintf(stderr, "Unable to generate additional CGI Environment"
		 "variable -- ran out of memory!\n");
	 return 0;
      }
      if (prefix_len)
	 memcpy(p, "HTTP_", 5);
      req->cgi_env[req->cgi_env_index++] = p;
      return 1;
   } else {
      log_error_doc(req);
      fprintf(stderr, "Unable to generate additional CGI Environment"
	      "variable -- not enough space!\n");
   }
   return 0;
}

#define my_add_cgi_env(req, key, value) { \
    int ok = add_cgi_env(req, key, value, 0); \
    if (!ok) return 0; \
    }

const char *hydra_method_str(int method)
{
   char *w;
   switch (method) {
   case M_POST:
      w = "POST";
      break;
   case M_HEAD:
      w = "HEAD";
      break;
   case M_GET:
      w = "GET";
      break;
   default:
      w = "UNKNOWN";
      break;
   }
   return w;
}

/*
 * Name: complete_env
 *
 * Description: adds the known client header env variables
 * and terminates the environment array
 */

int complete_env(request * req)
{
   int i;
   char buf[22];
   const char *w;

   for (i = 0; common_cgi_env[i]; i++)
      req->cgi_env[i] = common_cgi_env[i];

   w = hydra_method_str(req->method);
   my_add_cgi_env(req, "REQUEST_METHOD", w);

   if (req->action)
      my_add_cgi_env(req, "REDIRECT_STATUS", "200");

   if (req->secure) {
      simple_itoa(ssl_port, buf);
   } else {
      simple_itoa(server_port, buf);
   }
   my_add_cgi_env(req, "SERVER_PORT", buf);
   my_add_cgi_env(req, "SERVER_NAME", req->hostname);

   /* NCSA and APACHE added -- not in CGI spec */
#ifdef USE_NCSA_CGI_ENV
   my_add_cgi_env( req, "DOCUMENT_ROOT", req->document_root);
#endif

   my_add_cgi_env(req, "SERVER_ADDR", req->local_ip_addr);
   my_add_cgi_env(req, "SERVER_PROTOCOL", req->http_version_str);
   my_add_cgi_env(req, "REQUEST_URI", req->request_uri);

   if (req->path_info)
      my_add_cgi_env(req, "PATH_INFO", req->path_info);

   if (req->path_translated)
      /* while path_translated depends on path_info,
       * there are cases when path_translated might
       * not exist when path_info does
       */
      my_add_cgi_env(req, "PATH_TRANSLATED", req->path_translated);

   my_add_cgi_env(req, "SCRIPT_NAME", req->script_name);

   if (req->query_string)
      my_add_cgi_env(req, "QUERY_STRING", req->query_string);
   my_add_cgi_env(req, "REMOTE_ADDR", req->remote_ip_addr);

   simple_itoa(req->remote_port, buf);
   my_add_cgi_env(req, "REMOTE_PORT", buf);

   if (req->method == M_POST) {
      if (req->content_type) {
	 my_add_cgi_env(req, "CONTENT_TYPE", req->content_type);
      } else {
	 my_add_cgi_env(req, "CONTENT_TYPE", default_type);
      }
      if (req->content_length) {
	 my_add_cgi_env(req, "CONTENT_LENGTH", req->content_length);
      }
   }
#ifdef ACCEPT_ON
   if (req->accept[0])
      my_add_cgi_env(req, "HTTP_ACCEPT", req->accept);
#endif

   if (req->cgi_env_index < CGI_ENV_MAX + 1) {
      req->cgi_env[req->cgi_env_index] = NULL;	/* terminate */
      return 1;
   }
   log_error_time();
   fprintf(stderr, "Not enough space in CGI environment for remainder"
	   " of variables.\n");
   return 0;
}

/*
 * Name: make_args_cgi
 *
 * Build argv list for a CGI script according to spec
 *
 */

void create_argv(request * req, char **aargv)
{
   char *p, *q, *r;
   int aargc;

   q = req->query_string;
   aargv[0] = req->pathname;

   /* here, we handle a special "indexed" query string.
    * Taken from the CGI/1.1 SPEC:
    * This is identified by a GET or HEAD request with a query string
    * with no *unencoded* '=' in it.
    * For such a request, I'm supposed to parse the search string
    * into words, according to the following rules:

    search-string = search-word *( "+" search-word )
    search-word   = 1*schar
    schar         = xunreserved | escaped | xreserved
    xunreserved   = alpha | digit | xsafe | extra
    xsafe         = "$" | "-" | "_" | "."
    xreserved     = ";" | "/" | "?" | ":" | "@" | "&"

    After parsing, each word is URL-decoded, optionally encoded in a system
    defined manner, and then the argument list
    is set to the list of words.


    Thus, schar is alpha|digit|"$"|"-"|"_"|"."|";"|"/"|"?"|":"|"@"|"&"

    As of this writing, escape.pl escapes the following chars:

    "-", "_", ".", "!", "~", "*", "'", "(", ")",
    "0".."9", "A".."Z", "a".."z",
    ";", "/", "?", ":", "@", "&", "=", "+", "\$", ","

    Which therefore means
    "=", "+", "~", "!", "*", "'", "(", ")", ","
    are *not* escaped and should be?
    Wait, we don't do any escaping, and nor should we.
    According to the RFC draft, we unescape and then re-escape
    in a "system defined manner" (here: none).

    The CGI/1.1 draft (03, latest is 1999???) is very unclear here.

    I am using the latest published RFC, 2396, for what does and does
    not need escaping.

    Since boa builds the argument list and does not call /bin/sh,
    (boa uses execve for CGI)
    */

   if (q && !strchr(q, '=')) {
      /* we have an 'index' style */
      q = strdup(q);
      if (!q) {
	 WARN("unable to strdup 'q' in create_argv!");
      }
      for (aargc = 1; q && (aargc < CGI_ARGC_MAX);) {
	 r = q;
	 /* for an index-style CGI, + is used to seperate arguments
	  * an escaped '+' is of no concern to us
	  */
	 if ((p = strchr(q, '+'))) {
	    *p = '\0';
	    q = p + 1;
	 } else {
	    q = NULL;
	 }
	 if (unescape_uri(r, NULL)) {
	    /* printf("parameter %d: %s\n",aargc,r); */
	    aargv[aargc++] = r;
	 }
      }
      aargv[aargc] = NULL;
   } else {
      aargv[1] = NULL;
   }
}


/*
 * Name: init_cgi
 *
 * Description: Called for GET/POST requests that refer to ScriptAlias
 * directories or application/x-httpd-cgi files.  Pipes are used for the
 * communication with the child. 
 * stderr remains tied to our log file; is this good?
 *
 * Returns:
 * 0 - error or NPH, either way the socket is closed
 * 1 - success
 */

int init_cgi(request * req)
{
   int child_pid;
   int pipes[2];

   SQUASH_KA(req);

   if (req->is_cgi == NPH || req->is_cgi == CGI 
      || req->is_cgi == CGI_ACTION) 
   {
      if (req->secure && complete_env_ssl(req) == 0) {
	 return 0;
      }
      if (complete_env(req) == 0) {
	 return 0;
      }
   }
#ifdef FASCIST_LOGGING
   {
      int i;
      for (i = 0; i < req->cgi_env_index; ++i)
	 fprintf(stderr, "%s - environment variable for cgi: \"%s\"\n",
		 __FILE__, req->cgi_env[i]);
   }
#endif

   if (req->is_cgi) {
      if (pipe(pipes) == -1) {
	 log_error_time();
	 perror("pipe");
	 return 0;
      }

      /* set the read end of the socket to non-blocking */
      if (set_nonblock_fd(pipes[0]) == -1) {
	 log_error_time();
	 perror("cgi-fcntl");
	 close(pipes[0]);
	 close(pipes[1]);
	 return 0;
      }
   } else {
      log_error_time();
      fprintf(stderr, "Non CGI in init_cgi()!\n");
      return 0;
   }

      child_pid = fork();
      switch (child_pid) {
      case -1:
	 /* fork unsuccessful */
	 log_error_time();
	 perror("fork");

	 close(pipes[0]);
	 close(pipes[1]);

	 send_r_error(req);
	 /* FIXME: There is aproblem here. send_r_error would work
	    for NPH and CGI, but not for GUNZIP.  Fix that. */
	 /* i'd like to send_r_error, but.... */
	 return 0;
	 break;
      case 0:
	 /* child */
	 if (req->is_cgi == CGI || req->is_cgi == NPH || req->is_cgi == CGI_ACTION) 
	 {
	    int l;
	    char *newpath;
	    char *c;

	    c = strrchr(req->pathname, '/');
	    if (!c) {
	        /* there will always be a '.' */
	        log_error_time();
	        WARN("unable to find '/' in req->pathname");
                close(pipes[1]);
	       _exit(1);
	    }

	    *c = '\0';
	    
	    if (chdir(req->pathname) != 0) {
	       log_error_time();
	       perror("chdir");
	       close(pipes[1]);
	       _exit(1);
	    }

            req->pathname = ++c;
            l = strlen(req->pathname) + 3;
            /* prefix './' */
            newpath = malloc(sizeof(char) * l);
            if (!newpath) {
               /* there will always be a '.' */
	       log_error_time();
	       perror("unable to malloc for newpath");
	       close(pipes[1]);
	       _exit(1);
	    }
	    newpath[0] = '.';
	    newpath[1] = '/';
	    memcpy(&newpath[2], req->pathname, l - 2); /* includes the trailing '\0' */
	    req->pathname = newpath;
	 }
	 
         /* close the 'read' end of the pipes[] */
         close(pipes[0]);

         /* tie cgi's STDOUT to our write end of pipe */
         if (dup2(pipes[1], STDOUT_FILENO) == -1) {
	        log_error_time();
	        perror("dup2 - pipes");
	        _exit(1);
         }
         close(pipes[1]);
	        
	 /* tie post_data_fd to POST stdin */
	 if (req->method == M_POST) {	/* tie stdin to file */
	    if (req->post_data_fd.pipe==0) {
  	       if (lseek(req->post_data_fd.fds[0], SEEK_SET, 0) == (off_t)-1) {
	          log_error_time();
	          perror("lseek");
	          _exit(1);
  	       }
  	    }

	    dup2(req->post_data_fd.fds[0], STDIN_FILENO);
	    close_tmp_fd( &req->post_data_fd);
	 }

	 umask(cgi_umask); /* change umask *again* u=rwx,g=rxw,o= */

	 /*
	  * tie STDERR to cgi_log_fd
	  * cgi_log_fd will automatically close, close-on-exec rocks!
	  * if we don't tied STDERR (current log_error) to cgi_log_fd,
	  *  then we ought to close it.
	  */
         if (cgi_log_fd) {
            dup2(cgi_log_fd, STDERR_FILENO);
            close( cgi_log_fd);
         }

	 if (req->is_cgi == NPH || req->is_cgi == CGI) {
	    char *aargv[CGI_ARGC_MAX + 1];
     	    create_argv(req, aargv);
	    execve(req->pathname, aargv, req->cgi_env);
	 } else if (req->is_cgi == CGI_ACTION) {
	    char *aargv[CGI_ARGC_MAX + 2];
	    aargv[0] = req->action;
     	    create_argv(req, &aargv[1]);
	    execve(req->action, aargv, req->cgi_env);
	 } else {
	    if (req->is_cgi == INDEXER_CGI)
	       execl(dirmaker, dirmaker, req->pathname, req->request_uri,
		     NULL);
	 }
	 /* execve failed */
	 WARN(req->pathname);
	 _exit(1);

	 break;			/* it doesn't matter, we never make it until here */

      default:
	 /* parent */
	 /* if here, fork was successful */
	 if (verbose_cgi_logs) {
	    log_error_time();
	    fprintf(stderr, "Forked child \"%s\" pid %d\n",
		    req->pathname, child_pid);
	 }

	 if (req->method == M_POST) {
	    close_tmp_fd( &req->post_data_fd);
	 }

	 /* NPH, etc... all go straight to the fd */

	 close(pipes[1]);
	 break;
      }

   /* we only get here in parent case, and
    * success.
    */

   req->data_fd = pipes[0];

   req->status = PIPE_READ;
   if (req->is_cgi == CGI || req->is_cgi == HIC_CGI || req->is_cgi == CGI_ACTION) 
   {
      req->cgi_status = CGI_PARSE;	/* got to parse cgi header */
      /* for cgi_header... I get half the buffer! */
      req->header_line = req->header_end = (req->buffer + BUFFER_SIZE / 2);
   } else {  /* NPH CGIs */
      req->cgi_status = CGI_BUFFER;
      /* I get all the buffer! */
      req->header_line = req->header_end = req->buffer;
   }

   /* reset req->filepos for logging (it's used in pipe.c) */
   /* still don't know why req->filesize might be reset though */
   req->filepos = 0;

   return 1;
}

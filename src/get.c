/*
 *  Hydra, an http server
 *  Copyright (C) 1995 Paul Phillips <paulp@go2net.com>
 *  Some changes Copyright (C) 1996,99 Larry Doolittle <ldoolitt@boa.org>
 *  Some changes Copyright (C) 1996-2002 Jon Nelson <jnelson@boa.org>
 *  Portions Copyright (C) 2002 Nikos Mavroyanopoulos <nmav@gnutls.org>
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

/* $Id: get.c,v 1.32 2003/11/03 10:59:45 nmav Exp $*/

#include "boa.h"
#include "socket.h"
#include "access.h"

/* local prototypes */
int get_cachedir_file(request * req, struct stat *statbuf);
int index_directory(request * req, char *dest_filename);
static int check_if_stuff(request * req);

/*
 * Name: init_get
 * Description: Initializes a non-script GET or HEAD request.
 *
 * Return values:
 *   0: finished or error, request will be freed
 *   1: successfully initialized, added to ready queue
 */

int init_get(server_params * params, request * req)
{
   int data_fd, saved_errno;
   struct stat statbuf;
   volatile int bytes;

#ifdef ENABLE_ACCESS_LISTS
   if (!access_allow(req->hostname, req->pathname)) {
	send_r_forbidden(req);
	return 0;
   }
#endif

   data_fd = open(req->pathname, O_RDONLY);
   saved_errno = errno;		/* might not get used */

   if (data_fd == -1) {
      log_error_doc(req);
      errno = saved_errno;
      perror("document open");

      if (saved_errno == ENOENT)
	 send_r_not_found(req);
      else if (saved_errno == EACCES)
	 send_r_forbidden(req);
      else
	 send_r_bad_request(req);
      return 0;
   }

   if (fstat(data_fd, &statbuf) == -1) {
      /* this is quite impossible, since the file
       * was opened before.
       */
      close(data_fd);
      send_r_not_found(req);
      return 0;
   }

   if (S_ISDIR(statbuf.st_mode)) {	/* directory */
      close(data_fd);		/* close dir */

      if (req->pathname[strlen(req->pathname) - 1] != '/') {
	 char buffer[3 * MAX_PATH_LENGTH + 128];
	 char * hostname;
	 
	 if (req->hostname==NULL || req->hostname[0] == 0)
	 	hostname = req->local_ip_addr;
	 else
	 	hostname = req->hostname;

	 create_url(buffer, sizeof(buffer), req->secure, hostname,
		    params->server_s[req->secure].port, req->request_uri);

	 send_r_moved_perm(req, buffer);
	 return 0;
      }
      data_fd = get_dir(req, &statbuf);	/* updates statbuf */

      if (data_fd == -1)	/* couldn't do it */
	 return 0;		/* errors reported by get_dir */
      else if (data_fd <= 1)
	 /* data_fd == 0 -> close it down, 1 -> continue */
	 return data_fd;
      /* else, data_fd contains the fd of the file... */
   }

   req->filesize = statbuf.st_size;
   req->last_modified = statbuf.st_mtime;

   /* Check the If-Match, If-Modified etc stuff.
    */
   if (req->if_types)
      if (check_if_stuff(req) == 0) {
	 close(data_fd);
	 return 0;
      }
   /* Move on */

   if (req->range_stop == 0)
      req->range_stop = statbuf.st_size;

   /* out of range! */
   if (req->range_start > statbuf.st_size ||
       req->range_stop > statbuf.st_size ||
       req->range_stop <= req->range_start) {
      /* here we catch illegal ranges. We also catch
       * illegal ranges because of unsupported features
       * where range_start == range_stop == -1.
       */
      send_r_range_unsatisfiable(req);
      close(data_fd);
      return 0;
   }

   if (req->method == M_HEAD || req->filesize == 0) {
      send_r_request_file_ok(req);
      close(data_fd);
      return 0;
   }

   req->filepos = req->range_start;

   if (req->range_stop > max_file_size_cache) {

      if (req->range_start == 0 && req->range_stop == statbuf.st_size)
	 send_r_request_file_ok(req);	/* All's well */
      else {
	 /* if ranges were used, then lseek to the start given
	  */
	 if (lseek(data_fd, req->range_start, SEEK_SET) == (off_t) - 1) {
	    close(data_fd);
	    send_r_not_found(req);
	    return 0;
	 }
	 send_r_request_partial(req);	/* All's well */
      }

      req_flush(req);		/* this should *always* complete due to
				   the size of the I/O buffers */
      req->data_fd = data_fd;
      
      if (req->secure) {
         req->status = PIPE_READ;
         req->cgi_status = CGI_BUFFER;
      } else {
         /* This sends data directly to the socket, and cannot
          * be used in TLS connections.
          */
         req->status = IOSHUFFLE;
      }

      req->header_line = req->header_end = req->buffer;
      req->pipe_range_stop = req->range_stop;
      return 1;
   }

   if (req->range_stop == 0) {	/* done */
      send_r_request_file_ok(req);	/* All's well *so far* */
      close(data_fd);
      return 1;
   }

   /* NOTE: I (Jon Nelson) tried performing a read(2)
    * into the output buffer provided the file data would
    * fit, before mmapping, and if successful, writing that
    * and stopping there -- all to avoid the cost
    * of a mmap.  Oddly, it was *slower* in benchmarks.
    */
   if (max_files_cache > 0) {
      req->mmap_entry_var = find_mmap(data_fd, &statbuf);
      if (req->mmap_entry_var == NULL) {
	 req->buffer_end = 0;
	 if (errno == ENOENT)
	    send_r_not_found(req);
	 else if (errno == EACCES)
	    send_r_forbidden(req);
	 else
	    send_r_bad_request(req);
	 close(data_fd);
	 return 0;
      }
      req->data_mem = req->mmap_entry_var->mmap;
   } else {			/* File caching is disabled.
				 */
      req->data_mem =
	  mmap(0, req->range_stop, PROT_READ, MAP_OPTIONS, data_fd, 0);
   }

   close(data_fd);		/* close data file */

   if (req->data_mem == MAP_FAILED) {
      boa_perror(req, "mmap");
      return 0;
   }

   if (req->range_start == 0 && req->range_stop == statbuf.st_size)
      send_r_request_file_ok(req);	/* All's well */
   else
      send_r_request_partial(req);	/* All's well */

   bytes = BUFFER_SIZE - req->buffer_end;

   /* bytes is now how much the buffer can hold
    * after the headers
    */

   if (bytes > 0) {
      if (bytes > req->range_stop - req->range_start)
	 bytes = req->range_stop - req->range_start;

      if (setjmp(params->env) == 0) {
	 params->handle_sigbus = 1;
	 memcpy(req->buffer + req->buffer_end,
		&req->data_mem[req->filepos], bytes);
	 params->handle_sigbus = 0;
	 /* OK, SIGBUS **after** this point is very bad! */
      } else {
	 char buf[30];
	 /* sigbus! */
	 log_error_doc(req);
	 reset_output_buffer(req);
	 send_r_error(req);
	 get_commonlog_time(buf);
	 fprintf(stderr, "%sGot SIGBUS in memcpy!\n", buf);
	 return 0;
      }
      req->buffer_end += bytes;
      req->filepos += bytes;
      if (req->range_stop == req->filepos) {
	 req_flush(req);
	 req->status = DONE;
      }
   }

   /* We lose statbuf here, so make sure response has been sent */
   return 1;
}

/*
 * Name: check_if_stuff
 * Description: Checks the If-Match, If-None-Match headers
 *
 * req->last_modified, and req->filesize MUST have been set
 * before calling this function. This function should be called
 * if req->if_types != 0.
 *
 * Return values:
 *  1: Successful, continue sending the file
 *  0: unsuccessful. We send the appropriate stuff. Close the connection.
 */

static int check_if_stuff(request * req)
{
   int comp = 0;
   char *broken_etag[MAX_COMMA_SEP_ELEMENTS];
   int broken_etag_size, i;
   char new_etag[MAX_ETAG_LENGTH];

   /* Although we allow multiple If-* directives to be used, we
    * actually use only one. The priority used is shown below.
    */

   /* First try IF_MODIFIED_SINCE 
    */
   if (req->if_types & IF_MODIFIED_SINCE) {
      if (!modified_since(req->last_modified, req->if_modified_since)) {
	 send_r_not_modified(req);
	 return 0;
      }
      return 1;
   }


   /* Then try IF_MATCH
    */
   if (req->if_types & IF_MATCH) {

      /* Check for the "*"
       */
      if (strncmp(req->if_match_etag, "\"*\"", 3) == 0) {
	 comp = 0;		/* comparison is always ok */
      } else {

	 /* Create the current ETag of the file.
	  */
	 create_etag(req->filesize, req->last_modified, new_etag);

	 /* Check if one of the ETags sent, match ours
	  */
	 break_comma_list(req->if_match_etag, broken_etag,
			  &broken_etag_size);

	 comp = 1;
	 for (i = 0; i < broken_etag_size; i++) {
	    comp = strcmp(broken_etag[i], new_etag);
	    if (comp == 0)	/* matches! */
	       break;
	 }


      }

      if (comp == 0)
	 return 1;
      send_r_precondition_failed(req);
      return 0;
   }

   /* Then try IF_RANGE
    */
   if (req->if_types & IF_RANGE) {
      if (req->if_range_etag[0] == '"') { /* ETag may contain a date, if If-Range
					   * was used.
		 			   */
	 /* Check for the "*"
	  */
	 if (strncmp(req->if_range_etag, "\"*\"", 3) == 0) {
	    comp = 0;		/* comparison is always ok */
	 } else {

	    /* Create the current ETag
	     */
	    create_etag(req->filesize, req->last_modified, new_etag);

	    /* Check if one of the ETags sent, match ours
	     */

	    break_comma_list(req->if_range_etag, broken_etag,
			     &broken_etag_size);

	    comp = 1;
	    for (i = 0; i < broken_etag_size; i++) {
	       comp = strcmp(broken_etag[i], new_etag);
	       if (comp == 0)	/* matches! */
		  break;
	    }


	 }
      } else {
	 comp = modified_since(req->last_modified, req->if_range_etag);
      }


      /* File didn't change */
      if (comp == 0)
	 return 1;

      /* File has been changed, but it is Ok, so send the whole 
       * file.
       */
      req->range_start = req->range_stop = 0;
      return 1;
   }

   /* Then try IF_NONE_MATCH
    */
   if (req->if_types & IF_NONE_MATCH) {
      /* Check for the "*"
       */
      if (strncmp(req->if_none_match_etag, "\"*\"", 3) == 0) {
	 comp = 0;		/* comparison is always ok */
      } else {

	 /* Create the current ETag
	  */
	 create_etag(req->filesize, req->last_modified, new_etag);

	 /* Check if one of the ETags sent, match ours
	  */

	 break_comma_list(req->if_none_match_etag, broken_etag,
			  &broken_etag_size);

	 comp = 1;
	 for (i = 0; i < broken_etag_size; i++) {
	    comp = strcmp(broken_etag[i], new_etag);
	    if (comp == 0)	/* matches! */
	       break;
	 }


      }

      if (comp == 0) {
	 send_r_not_modified(req);
	 return 0;
      } else {			/* it was modified */
	 send_r_precondition_failed(req);
	 return 0;
      }
   }

   /* Unsupported type ? */

   return 1;			/* do the request */
}

/*
 * Name: process_get
 * Description: Writes a chunk of data to the socket.
 *
 * Return values:
 *  -1: request blocked, move to blocked queue
 *   0: EOF or error, close it down
 *   1: successful write, recycle in ready queue
 */

int process_get(server_params * params, request * req)
{
   int bytes_written;
   volatile int bytes_to_write;

   bytes_to_write = req->range_stop - req->filepos;
   if (bytes_to_write > system_bufsize)
      bytes_to_write = system_bufsize;


   if (setjmp(params->env) == 0) {
      params->handle_sigbus = 1;

      bytes_written =
	  socket_send(req, req->data_mem + req->filepos, bytes_to_write);

      params->handle_sigbus = 0;
      /* OK, SIGBUS **after** this point is very bad! */
   } else {
      char buf[30];
      /* sigbus! */
      log_error_doc(req);
      /* sending an error here is inappropriate
       * if we are here, the file is mmapped, and thus,
       * a content-length has been sent. If we send fewer bytes
       * the client knows there has been a problem.
       * We run the risk of accidentally sending the right number
       * of bytes (or a few too many) and the client
       * won't be the wiser.
       */
      req->status = DEAD;
      get_commonlog_time(buf);
      fprintf(stderr, "%sGot SIGBUS in write(2)!\n", buf);
      return 0;
   }

   if (bytes_written < 0) {
      if (errno == EWOULDBLOCK || errno == EAGAIN)
	 return -1;
      /* request blocked at the pipe level, but keep going */
      else {
	 if (errno != EPIPE) {
	    log_error_doc(req);
	    /* Can generate lots of log entries, */
	    perror("write");
	    /* OK to disable if your logs get too big */
	 }
	 req->status = DEAD;
	 return 0;
      }
   }
   req->filepos += bytes_written;

   if (req->filepos == req->range_stop) {	/* EOF */
      return 0;
   } else
      return 1;			/* more to do */
}

/*
 * Name: get_dir
 * Description: Called from process_get if the request is a directory.
 * statbuf must describe directory on input, since we may need its
 *   device, inode, and mtime.
 * statbuf is updated, since we may need to check mtimes of a cache.
 * returns:
 *  -1 error
 *  0  cgi (either gunzip or auto-generated)
 *  >0  file descriptor of file
 */

int get_dir(request * req, struct stat *statbuf)
{

   char *directory_index;
   int data_fd;

   directory_index =
       find_and_open_directory_index(req->pathname, 0, &data_fd);

   if (directory_index) {	/* look for index.html first?? */
      if (data_fd != -1) {	/* user's index file */
	 int ret;

	 /* Check if we can execute the file
	  */

	 strcat(req->request_uri, directory_index);
	 req->pathname = realloc( req->pathname, strlen(req->pathname) +
	 	strlen( directory_index) + 1);
	 if (req->pathname == NULL) {
	     send_r_error( req);
	     return -1;
	 }
	 
	 strcat( req->pathname, directory_index);

	 ret = is_executable_cgi(req, directory_index);
	 if (ret != 0) {	/* it is a CGI */
	    close(data_fd);	/* we don't need it */
	    if (ret == -1) {
	       send_r_not_found(req);
	       return -1;
	    }
	    return init_cgi(req);
	 }

	 /* Not a cgi */

	 fstat(data_fd, statbuf);
	 return data_fd;
      }
      if (errno == EACCES) {
	 send_r_forbidden(req);
	 return -1;
      } else if (errno != ENOENT) {
	 /* if there is an error *other* than EACCES or ENOENT */
	 send_r_not_found(req);
	 return -1;
      }
   }

   /* only here if index.html, index.html.gz don't exist */
   if (dirmaker != NULL) {	/* don't look for index.html... maybe automake? */
      req->response_status = R_REQUEST_OK;
      SQUASH_KA(req);

      /* the indexer should take care of all headers */
      if (req->http_version > HTTP_0_9) {
	 req_write(req, HTTP_VERSION " 200 OK\r\n");
	 print_http_headers(req);
	 print_last_modified(req);
	 req_write(req, "Content-Type: " TEXT_HTML CRLF CRLF);
	 req_flush(req);
      }
      if (req->method == M_HEAD)
	 return 0;

      req->is_cgi = INDEXER_CGI;
      return init_cgi(req);
      /* in this case, 0 means success */
   } else if (cachedir) {
      return get_cachedir_file(req, statbuf);
   } else {			/* neither index.html nor autogenerate are allowed */
      send_r_forbidden(req);
      return -1;		/* nothing worked */
   }
}

int get_cachedir_file(request * req, struct stat *statbuf)
{

   char pathname_with_index[MAX_PATH_LENGTH];
   int data_fd;
   time_t real_dir_mtime;

   real_dir_mtime = statbuf->st_mtime;
   sprintf(pathname_with_index, "%s/dir.%u.%lu",
	   cachedir, (unsigned int) statbuf->st_dev, 
	      (unsigned long int)statbuf->st_ino);
   data_fd = open(pathname_with_index, O_RDONLY);

   if (data_fd != -1) {		/* index cache */

      fstat(data_fd, statbuf);
      if (statbuf->st_mtime > real_dir_mtime) {
	 statbuf->st_mtime = real_dir_mtime;	/* lie */
	 strcpy(req->request_uri, find_default_directory_index());	/* for mimetype */
	 return data_fd;
      }
      close(data_fd);
      unlink(pathname_with_index);	/* cache is stale, delete it */
   }
   if (index_directory(req, pathname_with_index) == -1)
      return -1;

   data_fd = open(pathname_with_index, O_RDONLY);	/* Last chance */
   if (data_fd != -1) {
      strcpy(req->request_uri, find_default_directory_index());	/* for mimetype */
      fstat(data_fd, statbuf);
      statbuf->st_mtime = real_dir_mtime;	/* lie */
      return data_fd;
   }

   boa_perror(req, "re-opening dircache");
   return -1;			/* Nothing worked. */

}

/*
 * Name: index_directory
 * Description: Called from get_cachedir_file if a directory html
 * has to be generated on the fly
 * returns -1 for problem, else 0
 * This version is the fastest, ugliest, and most accurate yet.
 * It solves the "stale size or type" problem by not ever giving
 * the size or type.  This also speeds it up since no per-file
 * stat() is required.
 */

int index_directory(request * req, char *dest_filename)
{
   DIR *request_dir;
   FILE *fdstream;
   struct dirent *dirbuf;
   int bytes = 0;
   char *escname = NULL;

   if (chdir(req->pathname) == -1) {
      if (errno == EACCES || errno == EPERM) {
	 send_r_forbidden(req);
      } else {
	 log_error_doc(req);
	 perror("chdir");
	 send_r_bad_request(req);
      }
      return -1;
   }

   request_dir = opendir(".");
   if (request_dir == NULL) {
      int errno_save = errno;
      send_r_error(req);
      log_error_time();
      fprintf(stderr, "directory \"%s\": ", req->pathname);
      errno = errno_save;
      perror("opendir");
      return -1;
   }

   fdstream = fopen(dest_filename, "w");
   if (fdstream == NULL) {
      boa_perror(req, "dircache fopen");
      closedir(request_dir);
      return -1;
   }

   bytes += fprintf(fdstream,
		    "<HTML><HEAD>\n<TITLE>Index of %s</TITLE>\n</HEAD>\n\n",
		    req->request_uri);
   bytes +=
       fprintf(fdstream, "<BODY>\n\n<H2>Index of %s</H2>\n\n<PRE>\n",
	       req->request_uri);

   while ((dirbuf = readdir(request_dir))) {
      if (!strcmp(dirbuf->d_name, "."))
	 continue;

      if (!strcmp(dirbuf->d_name, "..")) {
	 bytes += fprintf(fdstream,
			  " [DIR] <A HREF=\"../\">Parent Directory</A>\n");
	 continue;
      }

      if ((escname = escape_string(dirbuf->d_name, NULL)) != NULL) {
	 bytes += fprintf(fdstream, " <A HREF=\"%s\">%s</A>\n",
			  escname, dirbuf->d_name);
	 free(escname);
	 escname = NULL;
      }
   }
   closedir(request_dir);
   bytes += fprintf(fdstream, "</PRE>\n\n</BODY>\n</HTML>\n");

   fclose(fdstream);

   chdir(server_root);

   req->filesize = bytes;	/* for logging transfer size */
   return 0;			/* success */
}

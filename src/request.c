/*
 *  Hydra, an http server
 *  Copyright (C) 1995 Paul Phillips <paulp@go2net.com>
 *  Some changes Copyright (C) 1996,97 Larry Doolittle <ldoolitt@boa.org>
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

/* $Id: request.c,v 1.35 2003/11/03 10:59:45 nmav Exp $*/

#include "boa.h"
#include <stddef.h>		/* for offsetof */
#include "ssl.h"
#include "socket.h"

extern int boa_ssl;
int system_bufsize = 0;		/* Default size of SNDBUF given by system */

inline static void init_vhost_stuff(request * req, char *value);

/* function prototypes located in this file only */
static void free_request(server_params * params, request ** list_head_addr,
			 request * req);

/*
 * Name: new_request
 * Description: Obtains a request struct off the free list, or if the
 * free list is empty, allocates memory
 *
 * Return value: pointer to initialized request
 */

request *new_request(server_params * params)
{
   request *req;

   if (params->request_free) {
      req = params->request_free;	/* first on free list */
      dequeue(&params->request_free, params->request_free);	/* dequeue the head */
   } else {
      req = (request *) malloc(sizeof(request));
      if (!req) {
	 log_error_time();
	 perror("malloc for new request");
	 return NULL;
      }
   }
   memset(req, 0, offsetof(request, buffer) + 1);
   req->data_fd = -1;
   req->post_data_fd.fds[0] = req->post_data_fd.fds[1] = -1;

   return req;
}

#ifdef ENABLE_SMP
static pthread_mutex_t accept_mutex[2] = {
	PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER
	};
#endif

/* Keep 2 numbers. One for the plain connections, and one
 * for the secure ones (SSL).
 */
static long int total_global_connections[2] = { 0, 0 };

/* Decreases total_global_connections, but does some locking
 * too.
 */
inline static void decrease_global_total_connections(int ssl)
{
   /* if we do want to serve as much as possible, then
    * don't bother counting connections.
    */
   if (max_connections == INT_MAX && max_ssl_connections == INT_MAX)
      return;

#ifdef ENABLE_SMP
   pthread_mutex_lock(&accept_mutex[ssl]);
#endif
   total_global_connections[ssl]--;
#ifdef ENABLE_SMP
   pthread_mutex_unlock(&accept_mutex[ssl]);
#endif

}

/* Returns the number of total connections
 */
long int get_total_global_connections(int ssl)
{
long int ret;

#ifdef ENABLE_SMP
   pthread_mutex_lock(&accept_mutex[ssl]);
#endif
   ret = total_global_connections[ssl];
#ifdef ENABLE_SMP
   pthread_mutex_unlock(&accept_mutex[ssl]);
#endif
   return ret;

}

/*
 * Name: get_request
 *
 * Description: Polls the server socket for a request.  If one exists,
 * does some basic initialization and adds it to the ready queue;.
 */

void get_request(server_params * params, socket_type * server_s)
{
   int fd;			/* socket */
   struct SOCKADDR remote_addr;	/* address */
   struct SOCKADDR salocal;
   int remote_addrlen = sizeof(struct SOCKADDR);
   request *conn;		/* connection */
   int len;
   static int sockbufsize = SOCKETBUF_SIZE;
#ifdef ENABLE_SSL
   gnutls_session ssl_state = NULL;
#endif

   remote_addr.S_FAMILY = 0xdead;

#ifdef ENABLE_SMP
   /* We make use of the fact that server_s->secure is either
    * 0 or 1. 0 Is used for the non SSL mutex, and 1 for the
    * secure one.
    */
   pthread_mutex_lock(&accept_mutex[server_s->secure]);
#endif

   /* If we have reached our max connections limit
    */
   if ((!server_s->secure && total_global_connections[0] >= max_connections) ||
       (server_s->secure && total_global_connections[1] >= max_ssl_connections))
   {
      server_s->pending_requests = 0;
      goto unlock;
   }

   fd = accept(server_s->socket, (struct sockaddr *) &remote_addr,
	       &remote_addrlen);

   if (fd == -1) {
      if (errno != EAGAIN && errno != EWOULDBLOCK)
	 /* abnormal error */
	 WARN("accept");
      else
	 /* no requests */
	 server_s->pending_requests = 0;
      goto unlock;
   }

   /* only count, if we have enabled a connection limit */
   if (max_connections != INT_MAX || max_ssl_connections != INT_MAX) {
      total_global_connections[server_s->secure]++;
   }

#ifdef ENABLE_SMP
   /* No dead lock conditions here, since accept() is non blocking.
    */
   pthread_mutex_unlock(&accept_mutex[server_s->secure]);
#endif

   if (fd >= FD_SETSIZE) {
      WARN("Got fd >= FD_SETSIZE.");
      close(fd);
      return;
   }

#ifdef ENABLE_SSL
   if (server_s->secure) {
      ssl_state = initialize_ssl_session();
      if (ssl_state == NULL) {
	 WARN("Could not initialize SSL session.");
	 close(fd);
	 return;
      }

      gnutls_transport_set_ptr(ssl_state, (gnutls_transport_ptr)fd);
   }
#endif

   len = sizeof(salocal);

   if (getsockname(fd, (struct sockaddr *) &salocal, &len) != 0) {
      WARN("getsockname");
      close(fd);
      return;
   }

   conn = new_request(params);
   if (!conn) {
      close(fd);
      return;
   }

   conn->fd = fd;
#ifdef ENABLE_SSL
   conn->ssl_state = ssl_state;
#endif

   if (server_s->secure != 0)
      conn->secure = 1;
   else
      conn->secure = 0;

   if (server_s->secure != 0)
      conn->status = FINISH_HANDSHAKE;
   else
      conn->status = READ_HEADER;

   conn->header_line = conn->client_stream;
   conn->time_last = current_time;
   conn->kacount = ka_max;

   ascii_sockaddr(&salocal, conn->local_ip_addr, NI_MAXHOST);

   /* nonblocking socket */
   if (set_nonblock_fd(conn->fd) == -1)
      WARN("fcntl: unable to set new socket to non-block");

   /* set close on exec to true */
   if (set_cloexec_fd(conn->fd) == -1)
      WARN("fctnl: unable to set close-on-exec for new socket");

   /* Increase buffer size if we have to.
    * Only ask the system the buffer size on the first request,
    * and assume all subsequent sockets have the same size.
    */
   if (system_bufsize == 0) {
      len = sizeof(system_bufsize);
      if (getsockopt
	  (conn->fd, SOL_SOCKET, SO_SNDBUF, &system_bufsize, &len) == 0
	  && len == sizeof(system_bufsize)) {
	 ;
      } else {
	 WARN("getsockopt(SNDBUF)");
	 system_bufsize = sockbufsize;
      }
   }
   if (system_bufsize < params->sockbufsize) {
      if (setsockopt
	  (conn->fd, SOL_SOCKET, SO_SNDBUF, (void *) &params->sockbufsize,
	   sizeof(params->sockbufsize)) == -1) {
	 WARN("setsockopt: unable to set socket buffer size");
#ifdef DIE_ON_ERROR_TUNING_SNDBUF
	 exit(errno);
#endif
      }
   }

   init_vhost_stuff(conn, "");

   /* for log file and possible use by CGI programs */
   ascii_sockaddr(&remote_addr, conn->remote_ip_addr, NI_MAXHOST);

   /* for possible use by CGI programs */
   conn->remote_port = net_port(&remote_addr);

   params->status.requests++;

   socket_set_options(conn->fd);

   params->total_connections++;

   enqueue(&params->request_ready, conn);

   return;

 unlock:
#ifdef ENABLE_SMP
   pthread_mutex_unlock(&accept_mutex[server_s->secure]);
#endif
   return;
}


/*
 * Name: free_request
 *
 * Description: Deallocates memory for a finished request and closes
 * down socket.
 */

static void free_request(server_params * params, request ** list_head_addr,
			 request * req)
{
   int i;
   /* free_request should *never* get called by anything but
      process_requests */

   if (req->buffer_end && req->status != DEAD) {
      req->status = DONE;
      return;
   }
   /* put request on the free list */
   dequeue(list_head_addr, req);	/* dequeue from ready or block list */

   if (req->logline)		/* access log */
      log_access(req);

   if (req->mmap_entry_var)
      release_mmap(req->mmap_entry_var);
/* FIXME: Why is it needed? */
   else if (req->data_mem)
      munmap(req->data_mem, req->filesize);

   if (req->data_fd != -1)
      close(req->data_fd);

   close_tmp_fd(&req->post_data_fd);

   if (req->response_status >= 400)
      params->status.errors++;

   for (i = COMMON_CGI_COUNT; i < req->cgi_env_index; ++i) {
      if (req->cgi_env[i]) {
	 free(req->cgi_env[i]);
      } else {
	 log_error_time();
	 fprintf(stderr, "Warning: CGI Environment contains NULL value"
		 "(index %d of %d).\n", i, req->cgi_env_index);
      }
   }

   free(req->pathname);
   free(req->query_string);
   free(req->path_info);
   free(req->path_translated);
   free(req->script_name);

   if ((req->keepalive == KA_ACTIVE) &&
       (req->response_status < 500) && req->kacount > 0) {
      int bytes_to_move;

      request *conn = new_request(params);
      if (!conn) {
	 /* errors already reported */
	 enqueue(&params->request_free, req);
	 close(req->fd);
	 params->total_connections--;
	 decrease_global_total_connections(req->secure);
	 return;
      }
      conn->fd = req->fd;

#ifdef ENABLE_SSL
      if (req->secure != 0) {
	 conn->secure = 1;
	 conn->ssl_state = req->ssl_state;

	 conn->status = READ_HEADER;
      } else {
#endif
	 conn->secure = 0;
	 conn->status = READ_HEADER;
#ifdef ENABLE_SSL
	 conn->ssl_state = NULL;
      }
#endif

      conn->header_line = conn->client_stream;
      conn->kacount = req->kacount - 1;

      /* close enough and we avoid a call to time(NULL) */
      conn->time_last = req->time_last;

      /* for log file and possible use by CGI programs */
      memcpy(conn->remote_ip_addr, req->remote_ip_addr, NI_MAXHOST);
      memcpy(conn->local_ip_addr, req->local_ip_addr, NI_MAXHOST);

      /* for possible use by CGI programs */
      conn->remote_port = req->remote_port;

      conn->action = req->action;

      params->status.requests++;

      /* we haven't parsed beyond req->parse_pos, so... */
      bytes_to_move = req->client_stream_pos - req->parse_pos;

      if (bytes_to_move) {
	 memcpy(conn->client_stream,
		req->client_stream + req->parse_pos, bytes_to_move);
	 conn->client_stream_pos = bytes_to_move;
      }
      enqueue(&params->request_block, conn);

      BOA_FD_SET(conn, conn->fd, BOA_READ);

      enqueue(&params->request_free, req);

      return;
   }

   /*
      While debugging some weird errors, Jon Nelson learned that
      some versions of Netscape Navigator break the
      HTTP specification.

      Some research on the issue brought up:

      http://www.apache.org/docs/misc/known_client_problems.html

      As quoted here:

      "
      Trailing CRLF on POSTs

      This is a legacy issue. The CERN webserver required POST
      data to have an extra CRLF following it. Thus many
      clients send an extra CRLF that is not included in the
      Content-Length of the request. Apache works around this
      problem by eating any empty lines which appear before a
      request.
      "

      Boa will (for now) hack around this stupid bug in Netscape
      (and Internet Exploder)
      by reading up to 32k after the connection is all but closed.
      This should eliminate any remaining spurious crlf sent
      by the client.

      Building bugs *into* software to be compatable is
      just plain wrong
    */

   if (req->method == M_POST) {
      char buf[32768];

      socket_recv(req, buf, sizeof(buf));
   }
#ifdef ENABLE_SSL
   if (req->secure) {
      gnutls_bye(req->ssl_state, GNUTLS_SHUT_WR);
      gnutls_deinit(req->ssl_state);
   }
#endif
   close(req->fd);

   params->total_connections--;
   decrease_global_total_connections(req->secure);

   enqueue(&params->request_free, req);

   return;
}

/*
 * Name: process_requests
 *
 * Description: Iterates through the ready queue, passing each request
 * to the appropriate handler for processing.  It monitors the
 * return value from handler functions, all of which return -1
 * to indicate a block, 0 on completion and 1 to remain on the
 * ready list for more procesing.
 */

void process_requests(server_params * params, socket_type * server_s)
{
   int retval = 0;
   request *current, *trailer;

   if (server_s->pending_requests) {
      get_request(params, server_s);
#ifdef ORIGINAL_BEHAVIOR
      server_s->pending_requests = 0;
#endif
   }

   current = params->request_ready;

   while (current) {
      if (current->buffer_end &&	/* there is data in the buffer */
	  current->status != DEAD && current->status != DONE) {
	 retval = req_flush(current);
	 /*
	  * retval can be -2=error, -1=blocked, or bytes left
	  */
	 if (retval == -2) {	/* error */
	    current->status = DEAD;
	    retval = 0;
	 } else if (retval >= 0) {
	    /* notice the >= which is different from below?
	       Here, we may just be flushing headers.
	       We don't want to return 0 because we are not DONE
	       or DEAD */

	    retval = 1;
	 }
      } else {
	 switch (current->status) {
#ifdef ENABLE_SSL
	 case FINISH_HANDSHAKE:
	    retval = finish_handshake(current);
	    break;
	 case SEND_ALERT:
	    retval = send_alert(current);
	    break;
#endif
	 case READ_HEADER:
	 case ONE_CR:
	 case ONE_LF:
	 case TWO_CR:
	    retval = read_header(params, current);
	    break;
	 case BODY_READ:
	    retval = read_body(current);
	    break;
	 case BODY_WRITE:
	    retval = write_body(current);
	    break;
	 case WRITE:
	    retval = process_get(params, current);
	    break;
	 case PIPE_READ:
	    retval = read_from_pipe(current);
	    break;
	 case PIPE_WRITE:
	    retval = write_from_pipe(current);
	    break;
	 case IOSHUFFLE:
	    retval = io_shuffle(current);
	    break;
	 case DONE:
	    /* a non-status that will terminate the request */
	    retval = req_flush(current);
	    /*
	     * retval can be -2=error, -1=blocked, or bytes left
	     */
	    if (retval == -2) {	/* error */
	       current->status = DEAD;
	       retval = 0;
	    } else if (retval > 0) {
	       retval = 1;
	    }
	    break;
	 case DEAD:
	    retval = 0;
	    current->buffer_end = 0;
	    SQUASH_KA(current);
	    break;
	 default:
	    retval = 0;
	    fprintf(stderr, "Unknown status (%d), "
		    "closing!\n", current->status);
	    current->status = DEAD;
	    break;
	 }

      }

      if (params->sigterm_flag)
	 SQUASH_KA(current);

      /* we put this here instead of after the switch so that
       * if we are on the last request, and get_request is successful,
       * current->next is valid!
       */
      if (server_s->pending_requests)
	 get_request(params, server_s);

      switch (retval) {
      case -1:			/* request blocked */
	 trailer = current;
	 current = current->next;
	 block_request(params, trailer);
	 break;
      case 0:			/* request complete */
	 current->time_last = current_time;
	 trailer = current;
	 current = current->next;
	 free_request(params, &params->request_ready, trailer);
	 break;
      case 1:			/* more to do */
	 current->time_last = current_time;
	 current = current->next;
	 break;
      default:
	 log_error_time();
	 fprintf(stderr, "Unknown retval in process.c - "
		 "Status: %d, retval: %d\n", current->status, retval);
	 current = current->next;
	 break;
      }
   }
}

/* Initializes several stuff that depend on the sent HTTP
 * version number.
 *
 * Returns true on sucess, or 0 otherwise.
 */
inline static
int init_http_version_specific_stuff(request * req)
{
   if ( req->http_version==HTTP_1_1) {
      if (!req->keepalive_given)
	 req->keepalive = KA_ACTIVE;	/* keepalive is active by default */

      if (req->hostname_given == 0) {
	 return 0;
      }
   }

   return 1;			/* success */
}

/*
 * Name: process_logline
 *
 * Description: This is called with the first req->header_line received
 * by a request, called "logline" because it is logged to a file.
 * It is parsed to determine request type and method, then passed to
 * translate_uri for further parsing.  Also sets up CGI environment if
 * needed.
 */
#define SIMPLE_HTTP_VERSION "HTTP/0.9"
int process_logline(request * req)
{
   char *stop, *stop2;

   req->logline = req->client_stream;
   if (!memcmp(req->logline, "GET ", 4))
      req->method = M_GET;
   else if (!memcmp(req->logline, "HEAD ", 5))
      /* head is just get w/no body */
      req->method = M_HEAD;
   else if (!memcmp(req->logline, "POST ", 5))
      req->method = M_POST;
   else {
      log_error_doc(req);
      fprintf(stderr, "malformed request: \"%s\"\n", req->logline);
      send_r_not_implemented(req);
      return 0;
   }

   req->http_version_str = SIMPLE_HTTP_VERSION;
   req->http_version = HTTP_0_9;

   /* Guaranteed to find ' ' since we matched a method above */
   stop = req->logline + 3;
   if (*stop != ' ')
      ++stop;

   /* scan to start of non-whitespace */
   while (*(++stop) == ' ');

   stop2 = stop;

   /* scan to end of non-whitespace */
   while (*stop2 != '\0' && *stop2 != ' ')
      ++stop2;

   if (stop2 - stop > MAX_HEADER_LENGTH) {
      log_error_doc(req);
      fprintf(stderr, "URI too long %d: \"%s\"\n", MAX_HEADER_LENGTH,
	      req->logline);
      send_r_bad_request(req);
      return 0;
   }
   memcpy(req->request_uri, stop, stop2 - stop);
   req->request_uri[stop2 - stop] = '\0';

   if (*stop2 == ' ') {
      /* if found, we should get an HTTP/x.x */
      unsigned int p1, p2;

      /* scan to end of whitespace */
      ++stop2;
      while (*stop2 == ' ' && *stop2 != '\0')
	 ++stop2;

      /* scan in HTTP/major.minor */
      if (sscanf(stop2, "HTTP/%u.%u", &p1, &p2) == 2) {
	 /* HTTP/{0.9,1.0,1.1} */
	 if (p1 == 1) {		/* We accept all HTTP/1.x versions */
	    req->http_version_str = stop2;
	    switch(p2) {
	       case 0:
  	          req->http_version = HTTP_1_0;
  	          break;
  	       case 1:
  	       default:
  	          req->http_version = HTTP_1_1;
	    }
	 } else if (p1 > 1) {	/* major number > 1 is invalid for us */
	    goto BAD_VERSION;
	 }
      } else {
	 goto BAD_VERSION;
      }

   }

   if (req->method == M_HEAD && req->http_version == HTTP_0_9) {
      send_r_bad_request(req);
      return 0;
   }
   req->cgi_env_index = COMMON_CGI_COUNT;

   return 1;

 BAD_VERSION:
   log_error_doc(req);
   fprintf(stderr, "bogus HTTP version: \"%s\"\n", stop2);
   send_r_bad_request(req);
   return 0;
}

/*
 * Name: process_header_end
 *
 * Description: takes a request and performs some final checking before
 * init_cgi or init_get
 * Returns 0 for error or NPH, or 1 for success
 */

int process_header_end(server_params * params, request * req)
{
   char *p = NULL;

   if (!req->logline) {
      send_r_error(req);
      return 0;
   }

   /* Check if all the stuff matches the HTTP version
    * sent.
    */
   if (!init_http_version_specific_stuff(req)) {
      send_r_bad_request(req);
      return 0;
   }

   /* Percent-decode request */
   if (unescape_uri(req->request_uri, &p) == 0) {
      log_error_doc(req);
      fputs("Problem unescaping uri\n", stderr);
      send_r_bad_request(req);
      return 0;
   }

   if (p) {
      req->query_string = strdup(p);
      if (req->query_string == NULL) {
	 send_r_error(req);
	 return 0;
      }
   }

   /* clean pathname */
   clean_pathname(req->request_uri);

   if (req->request_uri[0] != '/') {
      send_r_bad_request(req);
      return 0;
   }

   if (translate_uri(req) == 0) {	/* unescape, parse uri */
      SQUASH_KA(req);
      return 0;			/* failure, close down */
   }

   if (req->method == M_POST) {
      req->post_data_fd =
	  create_temporary_file(1, boa_atoi(req->content_length));
      if (req->post_data_fd.fds[0] == -1)
	 return (0);

      if (req->post_data_fd.pipe == 0) {
	 if (set_cloexec_fd(req->post_data_fd.fds[0]) == -1) {
	    WARN("unable to set close-on-exec for req->post_data_fd!");
	    close_tmp_fd(&req->post_data_fd);
	    return (0);
	 }
      }

      return (1);		/* success */
   }

   if (req->is_cgi) {
      return init_cgi(req);
   }

   req->status = WRITE;
   return init_get(params, req);	/* get and head */
}

/* Parses HTTP/1.1 range values.
 */
static int parse_range(const char *value, off_t * val1,
		       off_t * val2)
{
   int len;
   char *p;

   *val1 = *val2 = 0;

   len = strlen(value);
   if (len < 7)
      return -1;

   /* we do not accept ranges of the form "bytes=10-20,21-30"
    */
   if (strchr(value, ',') != NULL)
      return -1;

   if (memcmp("bytes=", value, 6) != 0) {
      return -1;
   } else
      value += 6;

   while (*value == ' ')
      value++;
   if ((p = strchr(value, '-')) == NULL)
      return -1;

   if (value[0] == '-') {	/* Handle case "bytes=-1024" */
      *val1 = 0;
      *val2 = boa_atoll(&value[1]);
      return 0;
   } else {
      char buf[43];
      int len;

      /* two values of the form "xxx-yyy" */

      if ((len = strlen(value)) >= sizeof(buf))
	 return -1;

      memcpy(buf, value, len);
      buf[len] = 0;

      p = strchr(buf, '-');
      if (p == NULL)
	 return -1;
      *p = 0;
      p++;

      while (*p == ' ')
	 p++;

      *val1 = boa_atoll(buf);

      if (*p == '\0')		/* form: "xxx-" */
	 *val2 = 0;
      else
	 *val2 = boa_atoll(p);

      if (*val1 == -1)
	 return -1;

      return 0;
   }

   return -1;
}

inline static void init_range_stuff(request * req, char *value)
{
   off_t p1, p2;
   if (parse_range(value, &p1, &p2) == 0) {
      req->range_start = p1;
      req->range_stop = p2;
   } else {
      req->range_start = -1;
      req->range_stop = -1;
      log_error_doc(req);
      fprintf(stderr, "bogus range: \"%s\"\n", value);

      /* here we just ignore a bogus range,
       * but we have put illegal values in
       * range start and range stop, to
       * be detected in init_get().
       */
   }
}

inline static void init_vhost_stuff(request * req, char *value)
{
   virthost *vhost;
   int valuelen;

   valuelen = strlen(value);

   vhost = find_virthost(value, valuelen);

   if (vhost == NULL && value[0] != 0) {
      value = "";
      vhost = find_virthost("", 0);
   }

   if (vhost
       && (vhost->ip == NULL
	   || !memcmp(vhost->ip, req->local_ip_addr, vhost->ip_len))) {
      req->hostname = value;
      memcpy(req->document_root, vhost->document_root,
	     vhost->document_root_len + 1);
      if (vhost->user_dir)
	 memcpy(req->user_dir, vhost->user_dir, vhost->user_dir_len + 1);

   }

}

/*
 * Name: process_option_line
 *
 * Description: Parses the contents of req->header_line and takes
 * appropriate action.
 */

int process_option_line(request * req)
{
   char c, *value, *line = req->header_line;

   /* Start by aggressively hacking the in-place copy of the header line */

#ifdef FASCIST_LOGGING
   log_error_time();
   fprintf(stderr, "%s:%d - Parsing \"%s\"\n", __FILE__, __LINE__, line);
#endif

   value = strchr(line, ':');
   if (value == NULL)
      return 0;
   *value++ = '\0';		/* overwrite the : */
   to_upper(line);		/* header types are case-insensitive */
   while ((c = *value) && (c == ' ' || c == '\t'))
      value++;


   switch (line[0]) {

   case 'A':
      if (!memcmp(line, "ACCEPT", 7))
	 add_accept_header(req, value);
      else
	 goto just_add_header;
      break;

   case 'C':
      if (!memcmp(line, "CONTENT_TYPE", 13) && !req->content_type)
	 req->content_type = value;
      else if (!memcmp(line, "CONTENT_LENGTH", 15) && !req->content_length)
	 req->content_length = value;
      else if (!memcmp(line, "CONNECTION", 11) &&
	       ka_max && req->keepalive != KA_STOPPED) {
	 req->keepalive_given = 1;
	 req->keepalive = (!strncasecmp(value, "Keep-Alive", 10) ?
			   KA_ACTIVE : KA_STOPPED);
      } else
	 goto just_add_header;

      break;

   case 'H':
      if (!memcmp(line, "HOST", 4)) {
	 req->hostname_given = 1;
	 init_vhost_stuff(req, value);
	 if (!add_cgi_env(req, "HOST", value, 1))
	    return 0;
      } else
	 goto just_add_header;
      break;

   case 'I':
      if (!memcmp(line, "IF_", 3)) {
	 char *p = line + 3;

	 if (!memcmp(p, "MODIFIED_SINCE", 15) && !req->if_modified_since) {
	    req->if_types |= IF_MODIFIED_SINCE;
	    req->if_modified_since = value;

	 } else if (!memcmp(p, "MATCH", 5) && !req->if_match_etag) {
	    req->if_types |= IF_MATCH;
	    req->if_match_etag = value;

	 } else if (!memcmp(p, "NONE_MATCH", 10)
		    && !req->if_none_match_etag) {
	    req->if_types |= IF_NONE_MATCH;
	    req->if_none_match_etag = value;

	 } else if (!memcmp(p, "RANGE", 5) && !req->if_range_etag) {
	    req->if_types |= IF_RANGE;
	    req->if_range_etag = value;
	 }

	 if (!add_cgi_env(req, line, value, 1))
	    return 0;
	 break;
      } else
	 goto just_add_header;


   case 'R':
      /* Need agent and referer for logs */
      if (!memcmp(line, "REFERER", 8)) {
	 req->header_referer = value;
	 if (!add_cgi_env(req, "REFERER", value, 1))
	    return 0;
      } else if (!memcmp(line, "RANGE", 5)) {
	 init_range_stuff(req, value);
      } else goto just_add_header;
      break;
      
 
   case 'U':
      if (!memcmp(line, "USER_AGENT", 11)) {
	 req->header_user_agent = value;
	 if (!add_cgi_env(req, "USER_AGENT", value, 1))
	    return 0;
      } else
	 goto just_add_header;
      break;

   default:
   just_add_header:
      if (!add_cgi_env(req, line, value, 1))
	 return 0;
      break;

   }

   return 1;

}

/*
 * Name: add_accept_header
 * Description: Adds a mime_type to a requests accept char buffer
 *   silently ignore any that don't fit -
 *   shouldn't happen because of relative buffer sizes
 */

void add_accept_header(request * req, char *mime_type)
{
#ifdef ACCEPT_ON
   int l = strlen(req->accept);
   int l2 = strlen(mime_type);

   if ((l + l2 + 2) >= MAX_HEADER_LENGTH)
      return;

   if (req->accept[0] == '\0')
      strcpy(req->accept, mime_type);
   else {
      req->accept[l] = ',';
      req->accept[l + 1] = ' ';
      memcpy(req->accept + l + 2, mime_type, l2 + 1);
      /* the +1 is for the '\0' */
      /*
         sprintf(req->accept + l, ", %s", mime_type);
       */
   }
#endif
}

void free_requests(server_params * params)
{
   request *ptr, *next;

   ptr = params->request_free;
   while (ptr != NULL) {
      next = ptr->next;
      free(ptr);
      ptr = next;
   }
   params->request_free = NULL;
}

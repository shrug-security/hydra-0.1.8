/*
 *  Hydra, an http server
 *  Copyright (C) 1995 Paul Phillips <paulp@go2net.com>
 *  Some changes Copyright (C) 1996 Charles F. Randall <crandall@goldsys.com>
 *  Some changes Copyright (C) 1996 Larry Doolittle <ldoolitt@boa.org>
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

/* $Id: select.c,v 1.14 2003/01/26 11:25:39 nmav Exp $*/

#include "boa.h"
#include "loop_signals.h"

#ifndef USE_POLL

static void fdset_update(server_params *);

/* params->server_s[0] is the plain socket, while the 
 * params->server_s[1] is the ssl one.
 */
void *select_loop(void *_params)
{
   server_params *params = _params;
   struct timeval *timeout;

   FD_ZERO(&params->block_read_fdset);
   FD_ZERO(&params->block_write_fdset);

   /* preset max_fd */

   while (1) {

      handle_signals(params);

      /* reset max_fd */
      params->max_fd = -1;

      if (params->request_block)
	 /* move selected req's from request_block to request_ready */
	 fdset_update(params);

      /* any blocked req's move from request_ready to request_block */
      if (params->server_s[0].socket != -1)
	 process_requests(params, &params->server_s[0]);
#ifdef ENABLE_SSL
      if (params->server_s[1].socket != -1)
	 process_requests(params, &params->server_s[1]);
#endif

      if (!params->sigterm_flag) {
	 if (params->server_s[0].socket != -1)
	    BOA_FD_SET(req, params->server_s[0].socket,
		       &params->block_read_fdset);
#ifdef ENABLE_SSL
	 if (params->server_s[1].socket != -1)
	    BOA_FD_SET(req, params->server_s[1].socket,
		       &params->block_read_fdset);
#endif
      }

      SET_TIMEOUT(params->req_timeout.tv_sec, 1, -1);
      params->req_timeout.tv_usec = 0l;	/* reset timeout */

      if (params->req_timeout.tv_sec == -1)
	 timeout = NULL;
      else
	 timeout = params->req_timeout;

      if (select(params->max_fd + 1, &params->block_read_fdset,
		 &params->block_write_fdset, NULL, timeout) == -1) {
	 /* what is the appropriate thing to do here on EBADF */
	 if (errno == EINTR)
	    continue;		/* while(1) */
	 else if (errno != EBADF) {
	    DIE("select");
	 }
      }

      if (params->server_s[0].socket != -1
	  && FD_ISSET(params->server_s[0].socket,
		      &params->block_read_fdset))
	 params->server_s[0].pending_requests = 1;
#ifdef ENABLE_SSL
      if (params->server_s[1].socket != -1
	  && FD_ISSET(params->server_s[1].socket,
		      &params->block_read_fdset))
	 params->server_s[1].pending_requests = 1;
#endif
   }

   return NULL;
}

/*
 * Name: fdset_update
 *
 * Description: iterate through the blocked requests, checking whether
 * that file descriptor has been set by select.  Update the fd_set to
 * reflect current status.
 *
 * Here, we need to do some things:
 *  - keepalive timeouts simply close
 *    (this is special:: a keepalive timeout is a timeout where
       keepalive is active but nothing has been read yet)
 *  - regular timeouts close + error
 *  - stuff in buffer and fd ready?  write it out
 *  - fd ready for other actions?  do them
 */

static void fdset_update(server_params * params)
{
   request *current, *next;

   for (current = params->request_block; current; current = next) {
      time_t time_since = current_time - current->time_last;
      next = current->next;

      /* hmm, what if we are in "the middle" of a request and not
       * just waiting for a new one... perhaps check to see if anything
       * has been read via header position, etc... */
      if (current->kacount < ka_max &&	/* we *are* in a keepalive */
	  (time_since >= ka_timeout) &&	/* ka timeout */
	  !current->logline)	/* haven't read anything yet */
	 current->status = DEAD;	/* connection keepalive timed out */
      else if (time_since > REQUEST_TIMEOUT) {
	 log_error_doc(current);
	 fprintf(stderr, "connection timed out (%d seconds)\n",
		 time_since);
	 current->status = DEAD;
      }
      if (current->buffer_end && current->status < DEAD) {
	 if (FD_ISSET(current->fd, &params->block_write_fdset))
	    ready_request(params, current);
	 else {
	    BOA_FD_SET(current, current->fd, &params->block_write_fdset);
	 }
      } else {
	 switch (current->status) {
	 case IOSHUFFLE:
#ifndef HAVE_SENDFILE
	    if (current->buffer_end - current->buffer_start == 0) {
	       if (FD_ISSET(current->data_fd, &block_read_fdset))
		  ready_request(params, current);
	       break;
	    }
#endif
	 case WRITE:
	 case PIPE_WRITE:
	    if (FD_ISSET(current->fd, &params->block_write_fdset))
	       ready_request(params, current);
	    else {
	       BOA_FD_SET(current, current->fd,
			  &params->block_write_fdset);
	    }
	    break;
	 case BODY_WRITE:
	    if (FD_ISSET
		(current->post_data_fd.fds[1], &params->block_write_fdset))
	       ready_request(params, current);
	    else {
	       BOA_FD_SET(current, current->post_data_fd.fds[1],
			  &params->block_write_fdset);
	    }
	    break;
	 case PIPE_READ:
	    if (FD_ISSET(current->data_fd, &params->block_read_fdset))
	       ready_request(params, current);
	    else {
	       BOA_FD_SET(current, current->data_fd,
			  &params->block_read_fdset);
	    }
	    break;
	 case DONE:
	    if (FD_ISSET(current->fd, &params->block_write_fdset))
	       ready_request(params, current);
	    else {
	       BOA_FD_SET(current, current->fd,
			  &params->block_write_fdset);
	    }
	    break;
	 case DEAD:
	    ready_request(params, current);
	    break;
	 default:
	    if (FD_ISSET(current->fd, &params->block_read_fdset))
	       ready_request(params, current);
	    else {
	       BOA_FD_SET(current, current->fd, &params->block_read_fdset);
	    }
	    break;
	 }
      }
      current = next;
   }
}

#endif				/* USE_POLL */

/*
 *  Boa, an http server
 *  Copyright (C) 1995 Paul Phillips <paulp@go2net.com>
 *  Some changes Copyright (C) 1996 Charles F. Randall <crandall@goldsys.com>
 *  Some changes Copyright (C) 1996 Larry Doolittle <ldoolitt@boa.org>
 *  Some changes Copyright (C) 1996-2000 Jon Nelson <jnelson@boa.org>
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

/* $Id: poll.c,v 1.3 2003/01/22 07:51:50 nmav Exp $*/

#include "boa.h"
#include "loop_signals.h"

#ifdef USE_POLL

int pending_requests;

void update_blocked(server_params* params, struct pollfd pfd1[]);

void* select_loop(void* _params)
{
    server_params* params = _params;
    struct pollfd pfd1[2][MAX_FD];
    short which = 0, other = 1, temp;
    int server_pfd = -1;
    int ssl_server_pfd = -1;

    params->pfds = pfd1[which];
    params->pfd_len = 0;

    while (1) {
        int timeout;

        handle_signals( params);

        if (!params->sigterm_flag) {
            if (params->server_s[0].socket != -1) {
               server_pfd = params->pfd_len++;
               params->pfds[server_pfd].fd = params->server_s[0].socket;
               params->pfds[server_pfd].events = POLLIN | POLLPRI;
            }
            if (params->server_s[1].socket != -1) {
               ssl_server_pfd = params->pfd_len++;
               params->pfds[ssl_server_pfd].fd = params->server_s[1].socket;
               params->pfds[ssl_server_pfd].events = POLLIN | POLLPRI;
            }
        }

        /* If there are any requests ready, the timeout is 0.
         * If not, and there are any requests blocking, the
         *  timeout is ka_timeout ? ka_timeout * 1000, otherwise
         *  REQUEST_TIMEOUT * 1000.
         * -1 means forever
         */
	SET_TIMEOUT( timeout, 1000, -1);

        if (poll(params->pfds, params->pfd_len, timeout) == -1) {
            if (errno == EINTR)
                continue;       /* while(1) */
        }

        params->pfd_len = 0;
        if (!params->sigterm_flag) {
           if (params->pfds[server_pfd].revents & POLLIN)
          	params->server_s[0].pending_requests = 1;
           if (params->pfds[ssl_server_pfd].revents & POLLIN)
          	params->server_s[1].pending_requests = 1;
        }

        /* go through blocked and unblock them if possible */
        /* also resets params->pfd_len and pfd to known blocked */
        if (params->request_block) {
            update_blocked(params, pfd1[other]);
        }

        /* swap pfd */
        params->pfds = pfd1[other];
        temp = other;
        other = which;
        which = temp;

        /* process any active requests */
        if (params->server_s[0].socket != -1) process_requests(params, &params->server_s[0]);
#ifdef ENABLE_SSL
        if (params->server_s[1].socket != -1) process_requests(params, &params->server_s[1]);
#endif
    }

    return NULL;
}

/*
 * Name: update_blocked
 *
 * Description: iterate through the blocked requests, checking whether
 * that file descriptor has been set by select.  Update the fd_set to
 * reflect current status.
 *
 * Here, we need to do some things:
 *  - keepalive timeouts simply close
 *    (this is special:: a keepalive timeout is a timeout where
 *    keepalive is active but nothing has been read yet)
 *  - regular timeouts close + error
 *  - stuff in buffer and fd ready?  write it out
 *  - fd ready for other actions?  do them
 */

void update_blocked(server_params* params, struct pollfd pfd1[])
{
    request *current, *next = NULL;
    time_t time_since;

    for (current = params->request_block; current; current = next) {
        time_since = current_time - current->time_last;
        next = current->next;

        // FIXME::  the first below has the chance of leaking memory!
        //  (setting status to DEAD not DONE....)
        /* hmm, what if we are in "the middle" of a request and not
         * just waiting for a new one... perhaps check to see if anything
         * has been read via header position, etc... */
        if (current->kacount < ka_max && /* we *are* in a keepalive */
            (time_since >= ka_timeout) && /* ka timeout has passsed */
            !current->logline) { /* haven't read anything yet */
            current->status = DEAD; /* connection keepalive timed out */
            ready_request( params, current);
            continue;
        } else if (time_since > REQUEST_TIMEOUT) {
            log_error_doc(current);
            fprintf(stderr, "connection timed out (%d secs)\n", (int)time_since);
            current->status = DEAD;
            ready_request( params, current);
            continue;
        }

        if (params->pfds[current->pollfd_id].revents) {
            ready_request( params, current);
        } else {                /* still blocked */
            pfd1[params->pfd_len].fd = params->pfds[current->pollfd_id].fd;
            pfd1[params->pfd_len].events = params->pfds[current->pollfd_id].events;
            current->pollfd_id = params->pfd_len++;
        }
    }
}

#endif /* USE_POLL */

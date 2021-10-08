/*
 *  Hydra, an http server
 *  Copyright (C) 1995 Paul Phillips <paulp@go2net.com>
 *  Some changes Copyright (C) 1997 Jon Nelson <jnelson@boa.org>
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

/* $Id: queue.c,v 1.6 2002/10/26 20:58:48 nmav Exp $*/

#include "boa.h"
#include "queue.h"

/*
 * Name: block_request
 *
 * Description: Moves a request from the ready queue to the blocked queue
 */

void block_request(server_params* params, request * req)
{
    dequeue(&params->request_ready, req);
    enqueue(&params->request_block, req);

    if (req->buffer_end) {
        BOA_FD_SET( req, req->fd, BOA_WRITE);
    } else {
        switch (req->status) {
        case IOSHUFFLE:
#ifndef HAVE_SENDFILE
            if (req->buffer_end - req->buffer_start == 0) {
                BOA_FD_SET(req, req->data_fd, BOA_READ);
                break;
            }
#endif
        case WRITE:
        case PIPE_WRITE:
        case DONE:
            BOA_FD_SET( req, req->fd, BOA_WRITE);
            break;
        case PIPE_READ:
            BOA_FD_SET( req, req->data_fd, BOA_READ);
            break;
        case BODY_WRITE:
            BOA_FD_SET( req, req->post_data_fd.fds[1], BOA_WRITE);
            break;
        default:
            BOA_FD_SET( req, req->fd, BOA_READ);
            break;
        }
    }
}

/*
 * Name: ready_request
 *
 * Description: Moves a request from the blocked queue to the ready queue
 */

void ready_request(server_params* params, request * req)
{
    dequeue(&params->request_block, req);
    enqueue(&params->request_ready, req);

    if (req->buffer_end) {
        BOA_FD_CLR(req, req->fd, BOA_WRITE);
    } else {
        switch (req->status) {
        case IOSHUFFLE:
#ifndef HAVE_SENDFILE
            if (req->buffer_end - req->buffer_start == 0) {
                BOA_FD_CLR(req, req->data_fd, BOA_READ);
                break;
            }
#endif
        case WRITE:
        case PIPE_WRITE:
        case DONE:
            BOA_FD_CLR(req, req->fd, BOA_WRITE);
            break;
        case PIPE_READ:
            BOA_FD_CLR(req, req->data_fd, BOA_READ);
            break;
        case BODY_WRITE:
            BOA_FD_CLR(req, req->post_data_fd.fds[1], BOA_WRITE);
            break;
        default:
            BOA_FD_CLR(req, req->fd, BOA_READ);
        }
    }
}


/*
 * Name: dequeue
 *
 * Description: Removes a request from its current queue
 */

DEQUEUE_FUNCTION( dequeue, request)

/*
 * Name: enqueue
 *
 * Description: Adds a request to the head of a queue
 */

ENQUEUE_FUNCTION( enqueue, request)


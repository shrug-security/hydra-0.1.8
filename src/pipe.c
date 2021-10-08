/*
 *  Hydra, an http server
 *  Based on code Copyright (C) 1995 Paul Phillips <paulp@go2net.com>
 *  Some changes Copyright (C) 1997-1999 Jon Nelson <jnelson@boa.org>
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

/* $Id: pipe.c,v 1.8 2002/10/21 20:33:31 nmav Exp $*/

#include "boa.h"
#include "socket.h"

/*
 * Name: read_from_pipe
 * Description: Reads data from a pipe
 *
 * Return values:
 *  -1: request blocked, move to blocked queue
 *   0: EOF or error, close it down
 *   1: successful read, recycle in ready queue
 */

int read_from_pipe(request * req)
{
    int bytes_read, bytes_to_read;

    if (req->is_cgi) 
       bytes_to_read = BUFFER_SIZE - (req->header_end - req->buffer);
    else {
         /* if not a cgi, then read up to range_stop value. The init_get() should have
          * used lseek() for the range_start.
          */
       bytes_to_read = BUFFER_SIZE - (req->header_end - req->buffer);
       
       if (req->pipe_range_stop >= bytes_to_read)
          req->pipe_range_stop -= bytes_to_read;
       else {
          bytes_to_read = req->pipe_range_stop;
          
          if (bytes_to_read == 0) { /* no need to move below */
                  req->status = PIPE_WRITE;
                  req->cgi_status = CGI_DONE;
                  return 1;
          }
          req->pipe_range_stop = 0;
       }
    }

    if (bytes_to_read == 0) {   /* buffer full */
        if (req->cgi_status == CGI_PARSE) { /* got+parsed header */
            req->cgi_status = CGI_BUFFER;
            *req->header_end = '\0'; /* points to end of read data */
            /* Could the above statement overwrite data???
               No, because req->header_end points to where new data
               should begin, not where old data is.
             */
            return process_cgi_header(req); /* cgi_status will change */
        }
        req->status = PIPE_WRITE;
        return 1;
    }

    bytes_read = read(req->data_fd, req->header_end, bytes_to_read);
#ifdef FASCIST_LOGGING
    if (bytes_read > 0) {
        *(req->header_end + bytes_read) = '\0';
        fprintf(stderr, "pipe.c - read %d bytes: \"%s\"\n",
                bytes_read, req->header_end);
    } else
        fprintf(stderr, "pipe.c - read %d bytes\n", bytes_read);
    fprintf(stderr, "status, cgi_status: %d, %d\n", req->status,
            req->cgi_status);
#endif

    if (bytes_read == -1) {
        if (errno == EINTR)
            return 1;
        else if (errno == EWOULDBLOCK || errno == EAGAIN)
            return -1;          /* request blocked at the pipe level, but keep going */
        else {
	    req->status = DEAD;
            log_error_doc(req);
            perror("pipe read");
            return 0;
        }
    }
    *(req->header_end + bytes_read) = '\0';

    if (bytes_read == 0) { /* eof, write rest of buffer */
        req->status = PIPE_WRITE;
        if (req->cgi_status == CGI_PARSE) { /* hasn't processed header yet */
            req->cgi_status = CGI_DONE;
            *req->header_end = '\0'; /* points to end of read data */
            return process_cgi_header(req); /* cgi_status will change */
        }
        req->cgi_status = CGI_DONE;
        return 1;
    }

    req->header_end += bytes_read;

    return 1;
}

/*
 * Name: write_from_pipe
 * Description: Writes data previously read from a pipe
 *
 * Return values:
 *  -1: request blocked, move to blocked queue
 *   0: EOF or error, close it down
 *   1: successful write, recycle in ready queue
 */

int write_from_pipe(request * req)
{
    int bytes_written, bytes_to_write = req->header_end - req->header_line;

    if (bytes_to_write == 0) {
        if (req->cgi_status == CGI_DONE)
            return 0;

        req->status = PIPE_READ;
        req->header_end = req->header_line = req->buffer;
        return 1;
    }

    bytes_written = socket_send(req, req->header_line, bytes_to_write);

    if (bytes_written < 0) {
        if (bytes_written == BOA_E_AGAIN)
            return -1;          /* request blocked at the pipe level, but keep going */
        else if (bytes_written == BOA_E_INTR)
            return 1;
        else {
            req->status = DEAD;
            send_r_error(req);  /* maybe superfluous */
            log_error_doc(req);
            perror("pipe write");
            return 0;
        }
    }

    req->header_line += bytes_written;
    req->filepos += bytes_written;

    /* if there won't be anything to write next time, switch state */
    if (bytes_written == bytes_to_write) {
        req->status = PIPE_READ;
        req->header_end = req->header_line = req->buffer;
    }

    return 1;
}

#ifdef HAVE_SENDFILE
int io_shuffle(request *req)
{
    int foo;
    off_t filepos;

    foo = req->pipe_range_stop - req->filepos;
    if (foo > system_bufsize)
        foo = system_bufsize;

retrysendfile:
    filepos = req->filepos;
#ifdef HAVE_BSDSENDFILE
    foo = sendfile(req->fd, req->data_fd, req->filepos, foo, NULL, &filepos, 0);
#else /* Linux sendfile */
    foo = sendfile(req->fd, req->data_fd, &filepos, foo);
#endif
    req->filepos = filepos;

    if (foo >= 0) {
        if (req->filepos >= req->pipe_range_stop)
            return 0;
        return 1;
    } else {
        if (errno == EWOULDBLOCK || errno == EAGAIN)
            return -1;          /* request blocked at the pipe level, but keep going */
        else if (errno == EINTR)
            goto retrysendfile;
        else {
            req->status = DEAD;
            send_r_error(req);  /* maybe superfluous */
            log_error_doc(req);
            perror("sendfile write");
            return 0;
        }
    }
}
#else

/* always try to read unless data_fs is 0 (and there is space)
 * then try to write
 *
 * Return values:
 *  -1: request blocked, move to blocked queue
 *   0: EOF or error, close it down
 *   1: successful read, recycle in ready queue
 */

int io_shuffle(request * req)
{
    int bytes_to_read;
    int bytes_written, bytes_to_write;

    bytes_to_read = BUFFER_SIZE - req->buffer_end;

    if (bytes_to_read > 0 && req->data_fd) {
        int bytes_read;
    restartread:
        bytes_read = read(req->data_fd, req->buffer + req->buffer_end, bytes_to_read);

        if (bytes_read == -1) {
            if (errno == EINTR)
                goto restartread;
            else if (errno == EWOULDBLOCK || errno == EAGAIN) {
                /* not a fatal error, don't worry about it */
                /* buffer is empty, we're blocking on read! */
                if (req->buffer_end - req->buffer_start == 0)
                    return -1;
            } else {
                req->status = DEAD;
                log_error_doc(req);
                perror("ioshuffle read");
                return 0;
            }
        } else if (bytes_read == 0) { /* eof, write rest of buffer */
            close(req->data_fd);
            req->data_fd = -1;
        } else {
            req->buffer_end += bytes_read;
        }
    }

    bytes_to_write = req->buffer_end - req->buffer_start;
    if (bytes_to_write == 0) {
        if (req->data_fd == 0)
            return 0; /* done */
        req->buffer_end = req->buffer_start = 0;
        return 1;
    }

restartwrite:
    bytes_written = write(req->fd, req->buffer + req->buffer_start, bytes_to_write);

    if (bytes_written == -1) {
        if (errno == EWOULDBLOCK || errno == EAGAIN)
            return -1;          /* request blocked at the pipe level, but keep going */
        else if (errno == EINTR)
            goto restartwrite;
        else {
            req->status = DEAD;
            send_r_error(req);  /* maybe superfluous */
            log_error_doc(req);
            perror("ioshuffle write");
            return 0;
        }
    } else if (bytes_written == 0) {
    }

    req->buffer_start += bytes_written;
    req->filepos += bytes_written;

    if (bytes_to_write == bytes_written) {
        req->buffer_end = req->buffer_start = 0;
    }

     return 1;
}

#endif

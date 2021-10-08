/*
 * Copyright (C) 2002 Nikos Mavroyanopoulos
 *
 * This file is part of Hydra webserver.
 *
 * Hydra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Hydra is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include "boa.h"
#include "ssl.h"

ssize_t socket_recv( request* req, void* buf, size_t buf_size)
{
ssize_t bytes;

#ifdef ENABLE_SSL
	if ( req->secure) {
	    bytes = gnutls_record_recv(req->ssl_state,
				       buf, buf_size);

	    if (bytes < 0) {
		if (bytes == GNUTLS_E_INTERRUPTED)
		    return BOA_E_INTR;
		if (bytes == GNUTLS_E_AGAIN)	/* request blocked */
		    return BOA_E_AGAIN;
		if (bytes==GNUTLS_E_UNEXPECTED_PACKET_LENGTH) /* abnormal termination */
		    return 0;

		log_error_doc(req);
		fprintf(stderr, "TLS receiving error \"%s\"\n", gnutls_strerror( bytes));
		check_ssl_alert( req, bytes);
		return BOA_E_UNKNOWN;
	    }
	} else {
#endif
	    bytes =
		recv(req->fd, buf, buf_size, 0);

	    if (bytes == -1) {
		if (errno == EINTR)
		    return BOA_E_INTR;
		if (errno == EAGAIN || errno == EWOULDBLOCK)	/* request blocked */
		    return BOA_E_AGAIN;

		log_error_doc(req);
		perror("header read");	/* don't need to save errno because log_error_doc does */
		return BOA_E_UNKNOWN;
	    }

#ifdef ENABLE_SSL
	}
#endif
	
	return bytes;
}

ssize_t socket_send( request* req, const void* buf, size_t buf_size)
{
ssize_t bytes;

#ifdef ENABLE_SSL
	if ( req->secure) {
	    bytes = gnutls_record_send(req->ssl_state,
				       buf, buf_size);

	    if (bytes < 0) {
		if (bytes == GNUTLS_E_INTERRUPTED)
		    return BOA_E_INTR;
		if (bytes == GNUTLS_E_AGAIN)	/* request blocked */
		    return BOA_E_AGAIN;

		log_error_doc(req);
		fprintf(stderr, "TLS sending error \"%s\"\n", gnutls_strerror( bytes));
		return BOA_E_UNKNOWN;
	    }
	} else {
#endif
	    bytes =
		send(req->fd, buf, buf_size, 0);

	    if (bytes == -1) {
		if (errno == EINTR)
		    return BOA_E_INTR;
		if (errno == EPIPE)
		    return BOA_E_PIPE;
		if (errno == EAGAIN || errno == EWOULDBLOCK)	/* request blocked */
		    return BOA_E_AGAIN;

		log_error_doc(req);
		perror("header read");	/* don't need to save errno because log_error_doc does */
		return BOA_E_UNKNOWN;
	    }

#ifdef ENABLE_SSL
	}
#endif
	
	return bytes;
}

#ifdef HAVE_TCP_CORK
void socket_flush( int fd)
{
  int zero = 0;

  /* This is to flush output buffers.
   */
  if (setsockopt( fd, IPPROTO_TCP, TCP_CORK,
            (void *) &zero, sizeof (zero)) == -1) {
      WARN("setsockopt: unable to set TCP_CORK");
  }
}
#endif

void socket_set_options( int fd) {
#ifdef HAVE_TCP_CORK /* Linux */
int one = 1;

  if (setsockopt(fd, IPPROTO_TCP, TCP_CORK,
     (void *) &one, sizeof (one)) == -1) 
  {
     WARN("setsockopt: unable to set TCP_CORK");
  }
#endif /* TCP_CORK */
}

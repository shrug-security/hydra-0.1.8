/*
 *  Hydra, an http server
 *  Copyright (C) 1998 Jon Nelson <jnelson@boa.org>
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

/* $Id: timestamp.c,v 1.6 2002/09/28 17:49:13 nmav Exp $*/

#include "boa.h"

void timestamp(void)
{
    log_error_time();
    fprintf(stderr, "%s: server version %s\n", SERVER_NAME, SERVER_VERSION);
    log_error_time();
    fprintf(stderr, "%s: server built " __DATE__ " at " __TIME__ ".\n", SERVER_NAME);
    log_error_time();
    fprintf(stderr, "%s: starting server pid=%d", SERVER_NAME, getpid());
    if (server_port && boa_ssl != 1)
       fprintf(stderr, ", port=%d", server_port);    
    if (ssl_port && boa_ssl > 0)
       fprintf(stderr, ", SSL port=%d", ssl_port);    
    fprintf(stderr, "\n");
}

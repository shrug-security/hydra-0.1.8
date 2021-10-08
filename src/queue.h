/*
 *  Hydra, an http server
 *  Copyright (C) 1995 Paul Phillips <paulp@go2net.com>
 *  Some changes Copyright (C) 1997 Jon Nelson <jnelson@boa.org>
 *  
 *  This was moved to macros by Nikos Mavroyanopoulos
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

/* Templates for Queue functions 
 */

#define DEQUEUE_FUNCTION( func_name, type) \
   void func_name(type ** head, type * req) \
   { \
      if (*head == req) \
          *head = req->next; \
      if (req->prev) \
          req->prev->next = req->next; \
      if (req->next) \
          req->next->prev = req->prev; \
      req->next = NULL; \
      req->prev = NULL; \
   }

#define ENQUEUE_FUNCTION( func_name, type) \
   void func_name(type ** head, type * req) \
   { \
      if (*head) \
          (*head)->prev = req;    /* previous head's prev is us */ \
      req->next = *head;          /* our next is previous head */ \
      req->prev = NULL;           /* first in list */ \
      *head = req;                /* now we are head */ \
   }


/*
 *  Boa, an http server
 *  Copyright (C) 2002 Nikos Mavroyanopoulos <nmav@gnutls.org>
 *  Based on patch for Boa by Peter Korsgaard <jacmet@sunsite.dk>
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
 */

/* $Id: access.c,v 1.3 2003/01/26 11:25:39 nmav Exp $ */

#include "boa.h"
#include "access.h"

#ifdef ENABLE_ACCESS_LISTS

#include <fnmatch.h>

void access_add(const char *hostname, const char *pattern, const int type)
{
   virthost *vhost;

   if (hostname == NULL || pattern == NULL) {
      DIE("NULL values sent to access_add");
   }

   vhost = find_virthost(hostname, 0);
   if (vhost == NULL) {
      fprintf(stderr, "Tried to add Access for non-existing host %s.\n",
	      hostname);
      exit(1);
   }

   vhost->n_access++;
   vhost->access_nodes =
       realloc(vhost->access_nodes,
	       vhost->n_access * sizeof(struct access_node));

   if (vhost->access_nodes == NULL) {
      DIE("out of memory");
   }

   vhost->access_nodes[vhost->n_access - 1].type = type;
   vhost->access_nodes[vhost->n_access - 1].pattern = strdup(pattern);

}				/* access_add */


int access_allow(const char *hostname, const char *file)
{
   int i;
   virthost *vhost = NULL;

   vhost = find_virthost(hostname, 0);
   if (vhost == NULL) {
      return ACCESS_ALLOW;
   }

   /* find first match in allow/deny rules */
   for (i = 0; i < vhost->n_access; i++) {
      if (fnmatch(vhost->access_nodes[i].pattern, file, 0) == 0) {
	 return vhost->access_nodes[i].type;
      }
   }
/* default to allow *//* FIXME-andreou */
   return ACCESS_ALLOW;
}				/* access_allow */

#endif				/* ENABLE_ACCESS_LISTS */

/* EOF */

/*
 *  Hydra, an http server
 *  Copyright (C) 2002 Nikos Mavroyanopoulos <nmav@gnutls.org>
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

/* $Id: action_cgi.c,v 1.1 2006-03-09 18:11:07 nmav Exp $ */

/* This file includes support for dynamically loaded HIC modules
 * All modules added to module_table[] will be dlopen()ed at startup.
 *
 * Also hic symbols will be resolved.
 */

#include "boa.h"


static action_module_st* module_hashtable[MODULE_HASHTABLE_SIZE];


/* add_cgi_action
 *
 * Like add_hic_module() but associates the file type with a
 * specific action (executable to run with)
 */

void add_cgi_action(const char *action, const char* file_type)
{
int hash;
action_module_st* old, *start;

    /* sanity checking */
    if (action == NULL || file_type == NULL) {
        DIE("NULL values sent to add_cgi_action");
    }

    hash = get_cgi_module_hash_value( file_type);
    start = old = module_hashtable[hash];
    
    if ( old != NULL) {
       /* find next empty */
       do {
          hash = (hash + 1) % MODULE_HASHTABLE_SIZE;
          
          old = module_hashtable[hash];

          if (start == old) {
             DIE("Module hashtable is full.");
          }
          
       } while( old != NULL);
    }
    
    /* old was found, and is empty. */
    
    old = malloc( sizeof(action_module_st));
    if (old==NULL) {
       DIE("malloc() failed.");
    }

    old->sym_prefix = NULL;
 
    old->content_type = strdup( file_type);
    if (old->content_type == NULL) {
       DIE("strdup() failed.");
    }

    old->content_type_len = strlen( file_type);

    old->action = strdup( action);
    if ( old->action == NULL) {
       DIE("strdup() failed.");    
    }

    module_hashtable[hash] = old;

    return;
}

/*
 * Name: find_cgi_action_appr_module
 *
 * Description: Locates the appropriate HIC module for the given file.
 * Actually ones needs this to get the dlsymed() functions.
 * 
 * Returns:
 *
 * a pointer to a hic_module_st structure or NULL if not found
 */

action_module_st *find_cgi_action_appr_module(const char *content_type, int content_type_len)
{
int i, hash;

   if (content_type == NULL) return NULL;
   if (content_type_len == 0) content_type_len = strlen( content_type);

   hash = get_cgi_module_hash_value( content_type);
   for (i=hash;i<MODULE_HASHTABLE_SIZE;i++) {
      if (module_hashtable[i] == NULL) break;

      if ( content_type_len != module_hashtable[i]->content_type_len) continue;

      if (memcmp( content_type, module_hashtable[i]->content_type, 
      	content_type_len) == 0) {
        /* FOUND! */
      	return module_hashtable[i];
      }
   }
 
   return NULL;

}


/*
 * Empties the hic modules table, deallocating any allocated memory.
 */

void dump_cgi_action_modules(void)
{
int i;

    for (i = 0; i < MODULE_HASHTABLE_SIZE; ++i) { /* these limits OK? */
        if (!module_hashtable[i]) continue;

        free( module_hashtable[i]->action);

        free( module_hashtable[i]);
        module_hashtable[i] = NULL;
    }
}

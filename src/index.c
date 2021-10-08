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

/* $Id: index.c,v 1.3 2002/09/28 16:32:37 nmav Exp $ */

#include "boa.h"

typedef struct {
   char* file;
   int file_size;
} dir_index_st;

static dir_index_st* directory_index_table[DIRECTORY_INDEX_TABLE_SIZE];

/*
 * Name: add_directory_index
 *
 * Description: add an index file to the directory index files table.
 */

void add_directory_index(const char *index_file)
{
    dir_index_st *new;
    int index_file_len;
    int i;

    /* sanity checking */
    if (index_file == NULL) {
        DIE("NULL values sent to add_directory_index");
    }

    index_file_len = strlen( index_file);
    
    if (index_file_len == 0) {
        DIE("empty values sent to add_directory_index");
    }

    for (i=0;i<DIRECTORY_INDEX_TABLE_SIZE;i++) {

       new = directory_index_table[ i];
       if (new) {
           if (!strcmp( index_file, new->file)) /* don't add twice */
              return;
       } else break; /* found an empty position */
    }

    if (new) {
        DIE("Directory index table is full. Increase DIRECTORY_INDEX_TABLE_SIZE");
    }

    new = malloc( sizeof( dir_index_st));
    if (!new) {
       DIE("out of memory adding directory index");
    }

    new->file = strdup( index_file);
    if (!new) {
        DIE("failed strdup");
    }

    new->file_size = index_file_len;
    
    directory_index_table[i] = new;

}

/*
 * Name: find_and_open_directory_index
 *
 * Description: Locates one index file in the directory given.
 *  Also opens the file and returns the data_fd.
 *
 * Returns:
 *
 * a pointer to the index file or NULL if not found
 */

char *find_and_open_directory_index(const char *directory, int directory_len, int* data_fd)
{
char pathname_with_index[MAX_PATH_LENGTH + 1];
int total_size, i;

   *data_fd = -1;

   if (directory_len == 0) directory_len = strlen( directory);
   if (directory_len > MAX_PATH_LENGTH) return NULL;

   memcpy( pathname_with_index, directory, directory_len);


   for (i=0;i<DIRECTORY_INDEX_TABLE_SIZE;i++) {
      if ( !directory_index_table[i]) break;

      total_size = directory_index_table[i]->file_size + directory_len;
      if ( total_size > MAX_PATH_LENGTH) continue;

      memcpy( &pathname_with_index[directory_len], directory_index_table[i]->file, 
      	directory_index_table[i]->file_size);
      	
      pathname_with_index[total_size] = 0;

      *data_fd = open(pathname_with_index, O_RDONLY);	

      /* If we couldn't access the file, then return the
       * filename as usual, and a data_fd (-1), with the
       * proper errno.
       */
      if (*data_fd == -1 && errno != EACCES) continue;
      
      /* data_fd > 0 -- found index! */
      return directory_index_table[i]->file;
   }
   
   return NULL;

}

/*
 * Name: find_default_directory_index
 *
 * Description: Returns the first directory index file, in the list
 *
 * Returns:
 *
 * a pointer to the index file or NULL if not found
 */

char *find_default_directory_index()
{
   if (directory_index_table[0] == NULL) return NULL;
   return directory_index_table[0]->file;
}


/*
 * Empties the virthost hashtable, deallocating any allocated memory.
 */

void dump_directory_index(void)
{
    int i;

    for (i = 0; i < DIRECTORY_INDEX_TABLE_SIZE; ++i) { /* these limits OK? */
        if (directory_index_table[i]) {
            free( directory_index_table[i]->file);
            free( directory_index_table[i]);
            directory_index_table[i] = NULL;
        }
    }
}

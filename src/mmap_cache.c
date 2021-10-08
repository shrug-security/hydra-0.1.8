/*
 *  Hydra, an http server
 *  Copyright (C) 1999 Larry Doolittle <ldoolitt@boa.org>
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

/* $Id: mmap_cache.c,v 1.14 2003/01/26 11:25:39 nmav Exp $*/

#include "boa.h"

#ifdef ENABLE_SMP
pthread_mutex_t mmap_lock = PTHREAD_MUTEX_INITIALIZER;
#endif

int mmap_list_entries_used = 0;
int mmap_list_total_requests = 0;
int mmap_list_hash_bounces = 0;

#ifdef USE_MMAP_LIST

static int previous_max_files_cache = 0;

/* define local table variable */
static struct mmap_entry* mmap_list;


struct mmap_entry *find_mmap(int data_fd, struct stat *s)
{
   char *m;
   int i, start;

   if ( max_files_cache == 0) return NULL;

#ifdef ENABLE_SMP
   pthread_mutex_lock(&mmap_lock);
#endif
   mmap_list_total_requests++;
   i = start = MMAP_LIST_HASH(s->st_dev, s->st_ino, s->st_size);

   for (;mmap_list[i].available;) {
      if (mmap_list[i].dev == s->st_dev && mmap_list[i].ino == s->st_ino
	  && mmap_list[i].len == s->st_size) {
	 mmap_list[i].use_count++;
	 mmap_list[i].times_used++;

#ifdef DEBUG0
	 fprintf(stderr,
		 "Old mmap_list entry %d use_count now %d (hash was %d)\n",
		 i, mmap_list[i].use_count, start);
#endif
#ifdef ENABLE_SMP
	 pthread_mutex_unlock(&mmap_lock);
#endif
	 return &mmap_list[i];
      }
      mmap_list_hash_bounces++;
      i = MMAP_LIST_NEXT(i);

      if (i == start) {
         i = cleanup_mmap_list(0);
         if (i != -1) break; /* if we found an empty index */
         /* otherwise no space could be cleaned. So say bye!!
          */
#ifdef ENABLE_SMP
	 pthread_mutex_unlock(&mmap_lock);
#endif
	 return NULL;
      }

   }

   /* didn't find an entry that matches our dev/inode/size.
      There might be an entry that matches later in the table,
      but that _should_ be rare.  The worst case is that we
      needlessly mmap() a file that is already mmap'd, but we
      did that all the time before this code was written,
      so it shouldn't be _too_ bad.
    */

   m = mmap(0, s->st_size, PROT_READ, MAP_OPTIONS, data_fd, 0);

   if ( m == MAP_FAILED) {
      /* boa_perror(req,"mmap"); */
      return NULL;
   }
#ifdef DEBUG0
   fprintf(stderr,
	   "New mmap_list entry %d (hash was %d) [ino: %u size: %u]\n", i,
	   start, s->st_ino, s->st_size);
#endif
   mmap_list_entries_used++;
   mmap_list[i].dev = s->st_dev;
   mmap_list[i].ino = s->st_ino;
   mmap_list[i].len = s->st_size;
   mmap_list[i].mmap = m;
   mmap_list[i].use_count = 1;
   mmap_list[i].available = 1;
   mmap_list[i].times_used = 1;

#ifdef ENABLE_SMP
   pthread_mutex_unlock(&mmap_lock);
#endif
   return &mmap_list[i];
}

/* Removes all entries in the mmap list that are not used and
 * have been used less times than the average of all.
 * No locking here. The caller has to do the proper locking.
 *
 * Return values:
 * -1 failed. Could not make any space on the list
 * >=0 an index number, of an empty element in the list.
 *
 */
int cleanup_mmap_list(int all)
{
   int i, avg = 0;
   int ret = -1;
#ifdef DEBUG
   int count = 0;

   fprintf(stderr, "Cleaning up mmap_list. Entries: %d.\n", mmap_list_entries_used);
#endif

   if (all != 0) goto remove_all_unused;

   /* The algorithm here is:
    * 1. Calculate the average of all times used
    * 2. Remove all entries that have been used less than
    *    'average' times. Also remove entries that their hash does not
    *    equal their index. This is to avoid duplicate entries.
    */
   for (i = 0; i < max_files_cache; i++) {
      if (mmap_list[i].available) {
         avg += mmap_list[i].times_used;
      }
   }

   avg /= i;

   for (i = 0; i < max_files_cache; i++) {
      if (mmap_list[i].available && (mmap_list[i].use_count == 0) &&
	  (mmap_list[i].times_used < avg || MMAP_LIST_HASH(mmap_list[i].dev, 
	  	mmap_list[i].ino, mmap_list[i].len) != i)) {
         
         ret = i;
	 munmap(mmap_list[i].mmap, mmap_list[i].len);
	 mmap_list[i].available = 0;
	 mmap_list_entries_used--;
#ifdef DEBUG
         count++;
#endif
      } else mmap_list[i].times_used = 0; /* zero all counters. */
   }
#ifdef DEBUG
   fprintf(stderr, "Removed %d entries from the mmap_hashtable (clean stage1)\n", count);
   count = 0;
#endif

   /* If no list elements were removed, then remove all that
    * are not used. This is our last resort! We shouldn't have
    * come here.
    */
   if (mmap_list_entries_used >= max_files_cache) {
      remove_all_unused:
      for (i = 0; i < max_files_cache; i++) {
	 if (mmap_list[i].available && mmap_list[i].use_count == 0) {

            ret = i;
	    munmap(mmap_list[i].mmap, mmap_list[i].len);
	    mmap_list[i].available = 0;
	    mmap_list_entries_used--;
#ifdef DEBUG
            count++;
#endif
	 }
      }
#ifdef DEBUG
   fprintf(stderr, "Removed %d entries from the mmap_hashtable (clean stage2)\n", count);
#endif

   }
   
   /* If we have come here and we didn't remove any list entries,
    * then all list entries are used or there is a bug above.
    */

#ifdef DEBUG
   fprintf(stderr, "Cleaned up mmap_list. Entries: %d.\n", mmap_list_entries_used);
#endif
    
   return ret;
}

void release_mmap(struct mmap_entry *e)
{
   if (!e)
      return;

#ifdef ENABLE_SMP
   pthread_mutex_lock(&mmap_lock);
#endif

   if (!e->use_count) {
#ifdef DEBUG
      fprintf(stderr, "mmap_list(%p)->use_count already zero!\n", e);
#endif
      goto finish;
   }

   e->use_count--;


 finish:
#ifdef ENABLE_SMP
   pthread_mutex_unlock(&mmap_lock);
#endif
   return;
}

struct mmap_entry *find_named_mmap(char *fname)
{
   int data_fd;
   struct stat statbuf;
   struct mmap_entry *e;
   data_fd = open(fname, O_RDONLY);
   if (data_fd == -1) {
      perror(fname);
      return NULL;
   }
   fstat(data_fd, &statbuf);
   if (S_ISDIR(statbuf.st_mode)) {
#ifdef DEBUG
      fprintf(stderr, "%s is a directory\n", fname);
#endif
      return NULL;
   }

   e = find_mmap(data_fd, &statbuf);
   close(data_fd);
   return e;
}

void mmap_reinit()
{
   
   if (max_files_cache > previous_max_files_cache) {
      mmap_list = realloc( mmap_list, sizeof(struct mmap_entry)*max_files_cache);
      if (mmap_list == NULL) {
         log_error_time();
         fprintf(stderr, "Could not allocate mmap list\n");
         exit(1);
      }
      memset( &mmap_list[previous_max_files_cache], 0, sizeof(struct mmap_entry)*
        (max_files_cache-previous_max_files_cache));
   } else {
      /* we cannot make the max file cache less than
       * the previous one, or we risk having some stray mmaped
       * stuff, in memory we cannot access.
       */
      if (max_files_cache < previous_max_files_cache) {
         log_error_time();
         fprintf(stderr, "Cannot not decrease the maximum files cache value, on runtime.\n"); 
      }

      max_files_cache = previous_max_files_cache;
   }
   previous_max_files_cache = max_files_cache;

}

void initialize_mmap()
{
   /* initialize the list array */
   mmap_list = calloc( 1, sizeof(struct mmap_entry)*max_files_cache);
   if (mmap_list == NULL) {
      log_error_time();
      fprintf(stderr, "Could not allocate mmap list\n");
      exit(1);
   }
   
   previous_max_files_cache = max_files_cache;
   return;
}

#endif				/* USE_MMAP_LIST */

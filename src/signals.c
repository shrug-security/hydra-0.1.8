/*
 *  Hydra, an http server
 *  Copyright (C) 1995 Paul Phillips <paulp@go2net.com>
 *  Some changes Copyright (C) 1996 Larry Doolittle <ldoolitt@boa.org>
 *  Some changes Copyright (C) 1996-99 Jon Nelson <jnelson@boa.org>
 *  Some changes Copyright (C) 1997 Alain Magloire <alain.magloire@rcsm.ee.mcgill.ca>
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

/* $Id: signals.c,v 1.26 2006-03-09 18:26:30 nmav Exp $*/

#include "boa.h"
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>		/* wait */
#endif
#include <signal.h>		/* signal */
#include "ssl.h"

#ifdef ENABLE_SMP
extern pthread_t father_id;
#endif

void sigsegv(int);
void sigbus(int);
void sigterm(int);
void sighup(int);
void sigint(int);
void sigchld(int);
void sigalrm(int);
void sigusr1(int);

/*
 * Name: init_signals
 * Description: Sets up signal handlers for all our friends.
 */

void init_signals(void)
{
   struct sigaction sa;

   sa.sa_flags = 0;

   sigemptyset(&sa.sa_mask);
   sigaddset(&sa.sa_mask, SIGSEGV);
   sigaddset(&sa.sa_mask, SIGBUS);
   sigaddset(&sa.sa_mask, SIGTERM);
   sigaddset(&sa.sa_mask, SIGHUP);
   sigaddset(&sa.sa_mask, SIGINT);
   sigaddset(&sa.sa_mask, SIGPIPE);
   sigaddset(&sa.sa_mask, SIGCHLD);
   sigaddset(&sa.sa_mask, SIGALRM);
   sigaddset(&sa.sa_mask, SIGUSR1);
   sigaddset(&sa.sa_mask, SIGUSR2);

   sa.sa_handler = sigsegv;
   sigaction(SIGSEGV, &sa, NULL);

   sa.sa_handler = sigbus;
   sigaction(SIGBUS, &sa, NULL);

   sa.sa_handler = SIG_IGN;
   sigaction(SIGPIPE, &sa, NULL);

   sa.sa_handler = sigchld;
   sigaction(SIGCHLD, &sa, NULL);

   sa.sa_handler = sigterm;
   sigaction(SIGTERM, &sa, NULL);

   sa.sa_handler = sighup;
   sigaction(SIGHUP, &sa, NULL);

   sa.sa_handler = sigint;
   sigaction(SIGINT, &sa, NULL);

   sa.sa_handler = sigalrm;
   sigaction(SIGALRM, &sa, NULL);

   sa.sa_handler = sigusr1;
   sigaction(SIGUSR1, &sa, NULL);

}

/* Blocks all signals that should be handled by
 * the main thread, so that other threads are
 * not annoyed.
 */
void block_main_signals()
{
   sigset_t sigset;

   sigemptyset(&sigset);
   sigaddset(&sigset, SIGALRM);
   sigaddset(&sigset, SIGUSR1);
   sigaddset(&sigset, SIGUSR2);
   sigaddset(&sigset, SIGTERM);
   sigaddset(&sigset, SIGINT);

   sigprocmask(SIG_BLOCK, &sigset, NULL);
}

void unblock_main_signals()
{
   sigset_t sigset;

   sigemptyset(&sigset);
   sigaddset(&sigset, SIGALRM);
   sigaddset(&sigset, SIGUSR1);
   sigaddset(&sigset, SIGUSR2);
   sigaddset(&sigset, SIGTERM);
   sigaddset(&sigset, SIGHUP);
   sigaddset(&sigset, SIGINT);

   sigprocmask(SIG_UNBLOCK, &sigset, NULL);
}

void block_sigusr2()
{
   sigset_t sigset;

   sigemptyset(&sigset);
   sigaddset(&sigset, SIGUSR2);

   sigprocmask(SIG_BLOCK, &sigset, NULL);
}

void unblock_sigusr2()
{
   sigset_t sigset;

   sigemptyset(&sigset);
   sigaddset(&sigset, SIGUSR2);

   sigprocmask(SIG_UNBLOCK, &sigset, NULL);
}


void sigsegv(int dummy)
{
   time(&current_time);
   log_error_time();
   fprintf(stderr, "caught SIGSEGV, dumping core in %s\n", tempdir);
   fclose(stderr);
   chdir(tempdir);
   abort();
}

void sigbus(int dummy)
{
   server_params *params = &global_server_params[0];

/* Note that in multithreaded cases the SIGBUS is catched
 * by the same thread that did the violation. So the following
 * code should be ok.
 */

#ifdef ENABLE_SMP
   pthread_t tid = pthread_self();
   int i;

   for (i = 0; i < global_server_params_size; i++) {
      if (pthread_equal(global_server_params[i].tid, tid)) {
	 params = &global_server_params[i];
	 break;
      }
   }
#endif

   if (params->handle_sigbus) {
      longjmp(params->env, dummy);
   }
   time(&current_time);
   log_error_time();
   fprintf(stderr, "caught SIGBUS, dumping core in %s\n", tempdir);
   fclose(stderr);
   chdir(tempdir);
   abort();
}

#define SET_PTH_SIGFLAG( flag, val) \
	   global_server_params[0].flag = val

#ifdef ENABLE_SMP
# define _SET_LOCAL_PTH_SIGFLAG( flag, val) \
        { pthread_t tid = pthread_self(); int i; int set = 0; \
           for (i=0;i<global_server_params_size;i++) { \
	      if ( pthread_equal( global_server_params[i].tid, tid)) { \
	         global_server_params[i].flag = val; \
	         set = 1; \
	         break; \
	      } \
	   }

# define SET_LOCAL_PTH_SIGFLAG( flag, val) \
	_SET_LOCAL_PTH_SIGFLAG( flag, val) }

#else
# define SET_LOCAL_PTH_SIGFLAG SET_PTH_SIGFLAG
#endif

void sigterm(int dummy)
{
   SET_PTH_SIGFLAG(sigterm_flag, 1);
}


void sigterm_stage1_run()
{				/* lame duck mode */
#ifdef ENABLE_SMP
   int i;
#endif

   time(&current_time);
   log_error_time();
   fputs("caught SIGTERM, starting shutdown\n", stderr);

#ifdef ENABLE_SMP
   {
      int ret;
      /* remember that the first thread is actual the main process.
       */
      for (i = 1; i < global_server_params_size; i++) {
	 /* terminate all threads */
	 if ((ret = pthread_cancel(global_server_params[i].tid)) != 0) {
	    log_error_time();
	    fprintf(stderr, "Could not cancel thread: %d. errno = %d.\n",
		    (int) global_server_params[i].tid, ret);
	    exit(1);
	 }
      }
   }
#endif

   if (global_server_params[0].server_s[0].socket != -1) {
      close(global_server_params[0].server_s[0].socket);
   }

   if (global_server_params[0].server_s[1].socket != -1) {
      close(global_server_params[0].server_s[1].socket);
   }

   SET_PTH_SIGFLAG(sigterm_flag, 2);
}


void sigterm_stage2_run()
{				/* lame duck mode */
   int i;

   log_error_time();
   fprintf(stderr,
	   "exiting Hydra normally (uptime %d seconds)\n",
	   (int) (current_time - start_time));
   chdir(tempdir);
   clear_common_env();
   dump_mime();
   dump_passwd();
   dump_virthost();
   dump_directory_index();
   dump_cgi_action_modules();

   for (i = 0; i < global_server_params_size; i++) {
      free_requests(&global_server_params[i]);
   }

   exit(0);
}


void sighup(int dummy)
{
   SET_LOCAL_PTH_SIGFLAG(sighup_flag, 1);
}

void sighup_run()
{
   int i;

   /* In sighup case, the father frees all memory, and
    * the childen terminate.
    */

   SET_LOCAL_PTH_SIGFLAG(sighup_flag, 0);


#ifdef ENABLE_SMP
   /* Kill all threads! */
   if (pthread_self() == father_id) {
      int ret;

      time(&current_time);
      log_error_time();
      fputs("caught SIGHUP, restarting\n", stderr);

      for (i = 1; i < global_server_params_size; i++) {
	 if ((ret = pthread_kill(global_server_params[i].tid, SIGHUP)) != 0) {
	    log_error_time();
	    fprintf(stderr, "Could not kill thread: %d. errno = %d.\n",
		    (int) global_server_params[i].tid, ret);
	 } else 
	 if ((ret=pthread_join( global_server_params[i].tid, NULL)) != 0) {
	    log_error_time();
	    fprintf(stderr, "Could not join thread: %d. errno = %d.\n",
	           (int) global_server_params[i].tid, ret);
	 }
      }
      log_error_time();
      fputs("Terminated all the threads in the pool.\n", stderr);

      for (i = 0; i < global_server_params_size; i++) {
	 free_requests(&global_server_params[i]);
      }

#endif
      for (i = 0; i < global_server_params_size; i++) {
	 BOA_FD_ZERO(&global_server_params[i].block_read_fdset);
	 BOA_FD_ZERO(&global_server_params[i].block_write_fdset);
      }

      /* Philosophy change for 0.92: don't close and attempt reopen of logfiles,
       * since usual permission structure prevents such reopening.
       */

      /* clear_common_env(); NEVER DO THIS */
      dump_mime();
      dump_passwd();
      dump_virthost();
      dump_directory_index();
      dump_cgi_action_modules();

      log_error_time();
      fputs("re-reading configuration files\n", stderr);
      read_config_files();

      /* We now need to dispatch the threads again */
      smp_reinit();
      ssl_reinit();
      mmap_reinit();

      log_error_time();
      fputs("successful restart\n", stderr);

#ifdef ENABLE_SMP
   } else {			/* a normal thread -- not father */
      pthread_exit(NULL);
   }
#endif

}

void sigint(int dummy)
{
   time(&current_time);
   log_error_time();
   fputs("caught SIGINT: shutting down\n", stderr);
   fclose(stderr);
   chdir(tempdir);
   exit(1);
}

void sigchld(int dummy)
{
   SET_LOCAL_PTH_SIGFLAG(sigchld_flag, 1);
}

void sigchld_run(void)
{
   int status;
   pid_t pid;

   SET_LOCAL_PTH_SIGFLAG(sigchld_flag, 0);

   while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
      if (verbose_cgi_logs) {
	 time(&current_time);
	 log_error_time();
	 fprintf(stderr, "reaping child %d: status %d\n", (int) pid,
		 status);
      }
   return;
}

void sigalrm(int dummy)
{
   SET_PTH_SIGFLAG(sigalrm_flag, 1);
}

void sigusr2(int dummy)
{
   return;
}

void sigusr1(int dummy)
{
   SET_PTH_SIGFLAG(sigusr1_flag, 1);
}

#ifdef ENABLE_SMP
extern pthread_mutex_t mmap_lock;
#endif

void sigalrm_run(void)
{
   SET_PTH_SIGFLAG(sigalrm_flag, 0);

#ifdef ENABLE_SSL
   if (boa_ssl)
      ssl_regenerate_params();
#endif

   log_error_time();
   fprintf(stderr, "Cleaning up file caches.\n");
#ifdef ENABLE_SMP
   pthread_mutex_lock(&mmap_lock);
#endif
   /* Clear all unused entries in the mmap list */
   cleanup_mmap_list(1);
#ifdef ENABLE_SMP
   pthread_mutex_unlock(&mmap_lock);
#endif

   if (maintenance_interval)
      alarm(maintenance_interval);

}

void sigusr1_run(void)
{
   int i;

   SET_PTH_SIGFLAG(sigusr1_flag, 0);

   time(&current_time);

   for (i = 0; i < global_server_params_size; i++) {
      log_error_time();
      fprintf(stderr, "Thread %d: %ld requests, %ld errors\n",
	      i + 1, global_server_params[i].status.requests,
	      global_server_params[i].status.errors);
   }

   /* Only print the running connections if we have set a connection
    * limit. That is because we do not count connections when we
    * have no connection limits.
    */
   if (max_connections != INT_MAX) {
      log_error_time();
      fprintf(stderr, "Running connections: %ld\n",
         get_total_global_connections(0));
   }

#ifdef ENABLE_SSL
   if ( max_ssl_connections != INT_MAX) {
         log_error_time();
      fprintf(stderr, "Running SSL connections: %ld\n",
         get_total_global_connections(1));
   }
#endif

   show_hash_stats();

}

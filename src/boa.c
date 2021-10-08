/*
 *  Hydra, an http server (based on Boa 0.94.13)
 *  Copyright (C) 1995 Paul Phillips <paulp@go2net.com>
 *  Some changes Copyright (C) 1996 Charles F. Randall <crandall@goldsys.com>
 *  Some changes Copyright (C) 1996 Larry Doolittle <ldoolitt@boa.org>
 *  Some changes Copyright (C) 1996-2002 Jon Nelson <jnelson@boa.org>
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

/* $Id: boa.c,v 1.28 2006-03-09 18:11:07 nmav Exp $*/

#include "boa.h"
#include "ssl.h"
#include <sys/resource.h>
#ifdef ENABLE_SMP
pthread_t father_id;
#endif

/* globals */
int backlog = SO_MAXCONN;
time_t start_time;

time_t current_time;


/* static to boa.c */
static void fixup_server_root(void);
static socket_type create_server_socket(int port, int);
void hic_init(void);
static void initialize_rlimits();
static void drop_privs(void);
static server_params *smp_init(socket_type server_s[2]);
static void create_server_names( void);

static int sock_opt = 1;
static int do_fork = 1;

int main(int argc, char **argv)
{
   int c;			/* command line arg */
   socket_type server_s[2] = { {-1, 0, 0, 0}, {-1, -1, 0, 0} };	/* boa socket */
   server_params *params;
   pid_t pid;

   /* set umask to u+rw, u-x, go-rwx */
   c = umask(077);
   if (c == -1) {
      perror("umask");
      exit(1);
   }

   { int devnullfd = -1;
      devnullfd = open("/dev/null", 0);

      /* make STDIN and STDOUT point to /dev/null */
      if (devnullfd == -1) {
         DIE("can't open /dev/null");
      }
   
      if (dup2(devnullfd, STDIN_FILENO) == -1) {
         DIE("can't dup2 /dev/null to STDIN_FILENO");
      }

      close(devnullfd);
   }

   /* but first, update timestamp, because log_error_time uses it */
   (void) time(&current_time);

   while ((c = getopt(argc, argv, "c:r:d")) != -1) {
      switch (c) {
      case 'c':
	 if (server_root)
	    free(server_root);
	 server_root = strdup(optarg);
	 if (!server_root) {
	    perror("strdup (for server_root)");
	    exit(1);
	 }
	 break;
      case 'r':
	 if (chdir(optarg) == -1) {
	    log_error_time();
	    perror("chdir (to chroot)");
	    exit(1);
	 }
	 if (chroot(optarg) == -1) {
	    log_error_time();
	    perror("chroot");
	    exit(1);
	 }
	 if (chdir("/") == -1) {
	    log_error_time();
	    perror("chdir (after chroot)");
	    exit(1);
	 }
	 break;
      case 'd':
	 do_fork = 0;
	 break;
      default:
	 fprintf(stderr, "Usage: %s [-c serverroot] [-r chroot] [-d]\n",
		 argv[0]);
	 exit(1);
      }
   }

   create_server_names();
   fixup_server_root();
   read_config_files();
   open_logs();

   if ((boa_ssl >= 2 || boa_ssl == 0) && server_port > 0) {
      server_s[0] = create_server_socket(server_port, 0);
   }

   if (boa_ssl != 0 && ssl_port > 0) {
      server_s[1] = create_server_socket(ssl_port, 1);
   }

   if (server_s[1].socket == -1 && server_s[0].socket == -1) {
      log_error_time();
      fprintf(stderr, "Could not initialize sockets\n");
      exit(1);
   }

   init_signals();
   initialize_rlimits();

   create_common_env();
   build_needs_escape();

   if (boa_ssl) {
      initialize_ssl();
   }

   initialize_mmap();

   /* background ourself */
   if (do_fork) {
      pid = fork();
   } else {
      pid = getpid();
   }

   switch (pid) {
      case -1:
	 /* error */
	 perror("fork");
	 exit(1);
	 break;
      case 0:
	 /* child, success */
	 break;
      default:
	 /* parent, success */
	 if(pid_file != NULL) {
	     FILE *PID_FILE = fopen(pid_file, "w");
	     if(PID_FILE != NULL) {
	        fprintf(PID_FILE, "%d", pid);
	        fclose(PID_FILE);
	     } else {
	        perror("fopen pid file");
	     }
	 }
	 if (do_fork)
  	    exit(0);
	 break;
   }

   drop_privs();

   /* main loop */
   timestamp();

   start_time = current_time;

   /* Blocks signals that are not supposed to be catched
    * by the children.
    */
   block_main_signals();

   /* spawn the children pool
    */
   params = smp_init(server_s);

   /* unblock signals for daddy
    */
   unblock_main_signals();

   /* regenerate parameters in that time interval 
    */
   if (maintenance_interval < MIN_MAINTENANCE_INTERVAL) {
      log_error_time();
      fprintf(stderr,
 	 "Changing maintenance mode time interval to %d minutes\n",
	 MIN_MAINTENANCE_INTERVAL / 60);
      maintenance_interval = MIN_MAINTENANCE_INTERVAL;
   }
   alarm(maintenance_interval);

   select_loop(params);

   return 0;
}

server_params *global_server_params;
int global_server_params_size = 0;

/* This function will return a server_params pointer. This
 * pointer is to be used as a pointer to the select loop.
 */
static server_params *smp_init(socket_type server_s[2])
{
   int i;
   server_params *params;

#ifdef ENABLE_SMP
   pthread_t tid;
   int max_threads = max_server_threads;

   father_id = pthread_self();
#else
   const int max_threads = 1;
#endif

   params = malloc(sizeof(server_params) * max_threads);
   if (params == NULL) {
      log_error_time();
      fprintf(stderr, "Could not allocate memory.\n");
      exit(1);
   }

   for (i = 0; i < max_threads; i++) {
      params[i].server_s[0] = server_s[0];
      params[i].server_s[1] = server_s[1];
      params[i].request_ready = NULL;
      params[i].request_block = NULL;
      params[i].request_free = NULL;

      /* for signal handling */
      params[i].sighup_flag = 0;
      params[i].sigchld_flag = 0;
      params[i].sigalrm_flag = 0;
      params[i].sigusr1_flag = 0;
      params[i].sigterm_flag = 0;

      params[i].sockbufsize = SOCKETBUF_SIZE;

      params[i].status.requests = 0;
      params[i].status.errors = 0;

      params[i].total_connections = 0;
      params[i].max_fd = 0;

      params[i].handle_sigbus = 0;
   }

#ifdef ENABLE_SMP
   params[0].tid = father_id;

   for (i = 1; i < max_threads; i++) {
      if (pthread_create(&tid, NULL, &select_loop, &params[i]) != 0) {
	 log_error_time();
	 fprintf(stderr, "Could not dispatch threads.\n");
	 exit(1);
      }
      params[i].tid = tid;
   }
#endif

   if (max_threads > 1) {
      log_error_time();
      fprintf(stderr,
	      "%s: Dispatched %d HTTP server threads.\n", SERVER_NAME,
	      max_threads);
   }

   global_server_params_size = max_threads;
   global_server_params = params;

   return &params[0];
}

void smp_reinit()
{
#ifdef ENABLE_SMP
   int i;
   server_params *params = global_server_params;
   int max_threads = max_server_threads;
#else
   int max_threads = 1;
#endif

   if (global_server_params_size < max_threads) {
      log_error_time();
      fprintf(stderr, "Cannot increase threads on runtime.\n");
      max_threads = global_server_params_size;
   }
#ifdef ENABLE_SMP
   for (i = 1; i < max_threads; i++) {
      pthread_t tid;
      if (pthread_create(&tid, NULL, &select_loop, &params[i]) != 0) {
	 log_error_time();
	 fprintf(stderr, "Could not dispatch threads.\n");
	 exit(1);
      }
      params[i].tid = tid;
   }
#endif

   if (max_threads > 0) {
      log_error_time();
      fprintf(stderr, "Regenerated a pool of %d threads.\n", max_threads);
   }

   return;
}


static socket_type create_server_socket(int port, int secure)
{
   socket_type server_s;

   server_s.secure = secure;
   server_s.port = port;

   server_s.socket = socket(SERVER_AF, SOCK_STREAM, IPPROTO_TCP);
   if (server_s.socket == -1) {
      DIE("unable to create socket");
   }

   /* server socket is nonblocking */
   if (set_nonblock_fd(server_s.socket) == -1) {
      DIE("fcntl: unable to set server socket to nonblocking");
   }

   /* close server socket on exec so cgi's can't write to it */
   if (set_cloexec_fd(server_s.socket) == -1) {
      DIE("can't set close-on-exec on server socket!");
   }

   /* reuse socket addr */
   if ((setsockopt
	(server_s.socket, SOL_SOCKET, SO_REUSEADDR, (void *) &sock_opt,
	 sizeof(sock_opt))) == -1) {
      DIE("setsockopt");
   }

   /* internet family-specific code encapsulated in bind_server()  */
   if (bind_server(server_s.socket, server_ip, port) == -1) {
      DIE("unable to bind");
   }

   /* listen: large number just in case your kernel is nicely tweaked */
   if (listen(server_s.socket, backlog) == -1) {
      DIE("unable to listen");
   }
   return server_s;
}

static void drop_privs(void)
{
   /* give away our privs if we can */
   if (getuid() == 0) {
      struct passwd *passwdbuf;
      passwdbuf = getpwuid(server_uid);
      if (passwdbuf == NULL) {
	 DIE("getpwuid");
      }
      if (initgroups(passwdbuf->pw_name, passwdbuf->pw_gid) == -1) {
	 DIE("initgroups");
      }
      if (setgid(server_gid) == -1) {
	 DIE("setgid");
      }
      if (setuid(server_uid) == -1) {
	 DIE("setuid");
      }
      /* test for failed-but-return-was-successful setuid
       * http://www.securityportal.com/list-archive/bugtraq/2000/Jun/0101.html
       */
      if (setuid(0) != -1 && server_uid != 0) {
	 DIE("icky Linux kernel bug!");
      }
   } else {
      if (server_gid || server_uid) {
	 log_error_time();
	 fprintf(stderr, "Warning: "
		 "Not running as root: no attempt to change"
		 " to uid %d gid %d\n", server_uid, server_gid);
      }
      server_gid = getgid();
      server_uid = getuid();
   }
}

/*
 * Name: fixup_server_root
 *
 * Description: Makes sure the server root is valid.
 *
 */

static void fixup_server_root()
{
   if (!server_root) {
#ifdef SERVER_ROOT
      server_root = strdup(SERVER_ROOT);
      if (!server_root) {
	 perror("strdup (SERVER_ROOT)");
	 exit(1);
      }
#else
      fputs(SERVER_NAME
	    ": don't know where server root is.  Please #define "
	    "SERVER_ROOT in defines.h\n"
	    "and recompile, or use the -c command line option to "
	    "specify it.\n", stderr);
      exit(1);
#endif
   }

   if (chdir(server_root) == -1) {
      fprintf(stderr, "Could not chdir to \"%s\": aborting\n",
	      server_root);
      exit(1);
   }

}

char boa_tls_version[64] = "\0";
char boa_version[] = "Server: "SERVER_NAME"/"SERVER_VERSION"\r\n";

static void create_server_names()
{
#ifdef ENABLE_SSL
   if ( boa_tls_version[0] == 0) {
      strcpy( boa_tls_version, "Server: "SERVER_NAME"/"SERVER_VERSION" GnuTLS/");
      strcat( boa_tls_version, gnutls_check_version(NULL));
      strcat( boa_tls_version, "\r\n");
   }
#endif
}

#ifdef HAVE_GETRLIMIT

#ifndef RLIMIT_NOFILE
# define RLIMIT_NOFILE RLIMIT_OFILE
#endif

static void initialize_rlimits( )
{
int c;
struct rlimit rl;

   /* Get system limits */
   c = getrlimit(RLIMIT_NOFILE, &rl);
   if (c < 0) {
      perror("getrlimit");
      exit(1);
   }

#ifdef HAVE_SETRLIMIT
   if (rl.rlim_max > rl.rlim_cur) {
      log_error_time();
      fprintf(stderr, "%s: Increasing max open files from %ld to %ld.\n", 
         SERVER_NAME, (unsigned long int)rl.rlim_cur, 
         (unsigned long int)rl.rlim_max);

      rl.rlim_cur = rl.rlim_max;
      c = setrlimit(RLIMIT_NOFILE, &rl);
      if (c < 0) {
          log_error_time();
          perror("setrlimit:");
      }
   }
#endif

   if (max_connections < 1)
      max_connections = INT_MAX;

   if (max_ssl_connections < 1)
      max_ssl_connections = INT_MAX;

}

#else /* rlimits are not present */
static void initialize_rlimits( )
{
   if (max_ssl_connections < 1)
      max_ssl_connections = INT_MAX;

   if (max_connections < 1)
      max_connections = INT_MAX;

   return;
}
#endif

/*
 *  Boa, an http server
 *  Copyright (C) 1995 Paul Phillips <paulp@go2net.com>
 *  Some changes Copyright (C) 1996,97 Larry Doolittle <ldoolitt@jlab.org>
 *  Some changes Copyright (C) 1997 Jon Nelson <jnelson@boa.org>
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

/* $Id: globals.h,v 1.34 2006-03-09 18:11:07 nmav Exp $*/

#ifndef _GLOBALS_H
#define _GLOBALS_H

#ifdef ENABLE_SSL
#include <gnutls/gnutls.h>
#endif

typedef struct {
  int socket;
  int secure; /* ssl or not. NOTE: 0 or 1. Nothing else. */
  int port;
  int pending_requests;
} socket_type;

struct mmap_entry {
  dev_t dev;
  ino_t ino;
  char *mmap;
  int use_count;
  size_t len;
  int available;
  int times_used;
};

/* This structure is used for both HIC loaded modules
 * and CGI Actions.
 */
typedef struct {
  char *sym_prefix;   /* ie. "_php" */
  char *content_type; /* ie. "application/x-httpd-php" */
  char *action;       /* ie. "/usr/bin/php4" */
  int content_type_len;
} action_module_st;

struct alias {
  char *fakename; /* URI path to file */
  char *realname; /* Actual path to file */
  int type;       /* ALIAS, SCRIPTALIAS, REDIRECT */
  int fake_len;   /* strlen of fakename */
  int real_len;   /* strlen of realname */
  struct alias *next;
};

typedef struct alias alias;

typedef struct {
  /* We use this, in order to store data to pipes if the
   * given POST data length, is smaller that PIPE_BUF;
   */
  int fds[2]; /* 0 is for reading, 1 for writing */
  int pipe;   /* non zero if it's a pipe */
} tmp_fd;

struct access_node {
  char *pattern;
  char type;
};

typedef struct _virthost {
  char *ip;              /* This virthost will be visible in this IP */
  char *host;            /* The hostname of the virtual host */
  char *document_root;   /* The document root of this virtual host */
  char *user_dir;        /* The user dir of this virtual host */
  int user_dir_len;      /* strlen of user_dir */
  int ip_len;            /* strlen of IP */
  int host_len;          /* strlen of hostname */
  int document_root_len; /* strlen of document root */
  alias *alias_hashtable[ALIAS_HASHTABLE_SIZE]; /* aliases in this virthost */

  int n_access;
  struct access_node *access_nodes;
  struct _virthost *next;
} virthost;

struct request { /* pending requests */
  int fd;        /* client's socket fd */
#ifdef USE_POLL
  int pollfd_id;
#endif
#ifdef ENABLE_SSL
  gnutls_session ssl_state;
  char *certificate_verified; /* a string that describes the output of the
                               * certificate verification function. Needed
                               * in CGIs.
                               */
#endif
  int secure;        /* whether ssl or not */
  int alert_to_send; /* in SEND_ALERT state */

  int status;            /* see #defines.h */
  time_t time_last;      /* time of last succ. op. */
  char *pathname;        /* pathname of requested file */
  off_t range_start;     /* send file from byte ... */
  off_t range_stop;      /* to byte */
  off_t pipe_range_stop; /* This is used only if the file is sent by the
                          * pipe_read() method. Indicates how many bytes to send
                          * from a file (actually a copy of range_stop, but it
                          * is modified. */
  int keepalive_given;   /* whether the keepalive was sent by the client */
  int keepalive;         /* keepalive status */
  int kacount;           /* keepalive count */

  int data_fd;    /* fd of data */
  off_t filesize; /* filesize */
  off_t filepos;  /* position in file */
  char *data_mem; /* mmapped/malloced char array */
  int method;     /* M_GET, M_POST, etc. */

  char *logline; /* line to log file */

  char *header_line; /* beginning of un or incompletely processed header line */
  char *header_end;  /* last known end of header, or end of processed data */
  int parse_pos;     /* how much have we parsed */
  int client_stream_pos; /* how much have we read... */

  int buffer_start; /* where the buffer starts */
  int buffer_end;   /* where the buffer ends */

  int http_version;       /* HTTP version numeric HTTP_0_9, HTTP_1_0 etc */
  char *http_version_str; /* HTTP/?.? of req */
  int response_status;    /* R_NOT_FOUND etc. */

  char *if_modified_since; /* If-Modified-Since */
  time_t last_modified;    /* Last-modified: */

  char *if_none_match_etag;
  char *if_match_etag;
  char *if_range_etag; /* These are the Etags sent by the client
                        * In If-* requests.
                        */
  int if_types;        /* If-Match, If-None-Match, If-Range
                        * and OR of the MATCH_* definitions.
                        */

  char local_ip_addr[NI_MAXHOST]; /* for virtualhost */
  int hostname_given;             /* For HTTP/1.1 checks. 0 if the
                                   * Host header was not found.
                                   */
  char *hostname;                 /* The hostname used in this request */
  char document_root[MAX_PATH_LENGTH + 1];
  char user_dir[MAX_USER_DIR_LENGTH + 1];

  /* CGI vars */

  int remote_port; /* could be used for ident */

  char remote_ip_addr[NI_MAXHOST]; /* after inet_ntoa */

  char *action; /* the action to run if CGI_ACTION cgi */
  int is_cgi;   /* true if CGI/NPH */
  int cgi_status;
  int cgi_env_index; /* index into array */

  /* Agent and referer for logfiles */
  char *header_user_agent;
  char *header_referer;

  tmp_fd post_data_fd; /* fd for post data tmpfile */

  char *path_info;       /* env variable */
  char *path_translated; /* env variable */
  char *script_name;     /* env variable */
  char *query_string;    /* env variable */
  char *content_type;    /* env variable */
  char *content_length;  /* env variable */

  struct mmap_entry *mmap_entry_var;

  struct request *next; /* next */
  struct request *prev; /* previous */

  /* everything below this line is kept regardless */
  char buffer[BUFFER_SIZE + 1];            /* generic I/O buffer */
  char request_uri[MAX_HEADER_LENGTH + 1]; /* uri */
  char client_stream[CLIENT_STREAM_SIZE];  /* data from client - fit or be hosed
                                            */
  char *cgi_env[CGI_ENV_MAX + 4];          /* CGI environment */

#ifdef ACCEPT_ON
  char accept[MAX_ACCEPT_LENGTH]; /* Accept: fields */
#endif
};

typedef struct request request;

struct status {
  long requests;
  long errors;
};

extern char *optarg; /* For getopt */
extern FILE *yyin;   /* yacc input */

typedef struct {
#ifdef ENABLE_SMP
  pthread_t tid;
#endif
  request *request_ready;
  request *request_block;
  request *request_free;

  socket_type server_s[2];

#ifdef USE_POLL
  struct pollfd *pfds;
  int pfd_len;
#else
  fd_set block_read_fdset;  /* fds blocked on read */
  fd_set block_write_fdset; /* fds blocked on write */
#endif

  struct timeval req_timeout;
  int sighup_flag;  /* 1 => signal has happened, needs attention */
  int sigchld_flag; /* 1 => signal has happened, needs attention */
  int sigalrm_flag; /* 1 => signal has happened, needs attention */
  int sigusr1_flag; /* 1 => signal has happened, needs attention */
  int sigterm_flag; /* lame duck mode */

  int max_fd;

  int sockbufsize;
  struct status status;
  int total_connections;

  /* for SIGBUS handling */
  jmp_buf env;
  int handle_sigbus;

} server_params;

/* global server variables */

extern int maintenance_interval;
extern int mmap_list_entries_used;
extern char *access_log_name;
extern char *error_log_name;
extern char *cgi_log_name;
extern int cgi_log_fd;
extern int use_localtime;

extern int max_files_cache;
extern int max_file_size_cache;

extern int boa_ssl;

extern int server_port;
extern int ssl_port;
extern uid_t server_uid;
extern gid_t server_gid;
extern char *server_admin;
extern char *server_root;
extern char *server_name;
extern char *server_ip;
extern int max_fd;

extern char *default_type;
extern char *default_charset;
extern char *dirmaker;
extern char *mime_types;
extern char *pid_file;
extern char *cachedir;

extern char *default_document_root;
extern int default_document_root_size;

extern int system_bufsize; /* Default size of SNDBUF given by system */

extern char *tempdir;
extern int tempdir_len;

extern char *cgi_path;
extern int single_post_limit;

extern int ka_timeout;
extern int ka_max;

extern time_t start_time;

extern int max_server_threads;

extern int cgi_umask;

extern long int max_connections;
extern long int max_ssl_connections;

long int get_total_global_connections(int ssl);

extern int verbose_cgi_logs;

extern int backlog;
extern time_t current_time;

/* Global stuff that is shared by all threads.
 * Use with extreme care, or don't use.
 */
extern server_params *global_server_params;
extern int global_server_params_size;

/* The default character set used.
 */
extern char *default_charset;

/* These contain a string of the form: "Server: Hydra/0.0.x\r\n"
 */
extern char boa_tls_version[];
extern char boa_version[];

#endif

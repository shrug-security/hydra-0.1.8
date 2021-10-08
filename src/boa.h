/*
 *  Boa, an http server
 *  Copyright (C) 1995 Paul Phillips <paulp@go2net.com>
 *  Some changes Copyright (C) 1996-99 Larry Doolittle <ldoolitt@jlab.org>
 *  Some changes Copyright (C) 1997-99 Jon Nelson <jnelson@boa.org>
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

/* $Id: boa.h,v 1.34 2006-03-09 18:11:07 nmav Exp $*/

#ifndef _BOA_H
#define _BOA_H

#include <errno.h>
#include <stdlib.h>             /* malloc, free, etc. */
#include <stdio.h>              /* stdin, stdout, stderr */
#include <string.h>             /* strdup */
#include <ctype.h>
#include <time.h>               /* localtime, time */
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>             /* OPEN_MAX */
#include <setjmp.h>

#include <netdb.h>
#include <netinet/in.h>

#include <sys/mman.h>
#include <sys/types.h>          /* socket, bind, accept */
#include <sys/socket.h>         /* socket, bind, accept, setsockopt, */
#include <sys/stat.h>           /* open */

#include "compat.h"             /* oh what fun is porting */
#include "defines.h"

#ifdef ENABLE_SMP
# include <pthread.h>
#endif

#ifdef HAVE_NETINET_TCP_H
# include <netinet/tcp.h>
#endif

#include "globals.h"


/* alias */
void add_alias(char* hostname, char *fakename, char *realname, int script);
int translate_uri(request * req);
int init_script_alias(request * req, alias * current, int uri_len);
void dump_alias( virthost*);

/* virthost */
void add_virthost(const char *host, const char *ip, const char* document_root, const char* user_dir);
virthost *find_virthost(const char *host, int hostlen);
void dump_virthost(void);

/* directory_index */
char *find_and_open_directory_index(const char *directory, int dirlen, int* fd);
void dump_directory_index(void);
void add_directory_index( const char* index);
char* find_default_directory_index( void);

/* config */
void read_config_files(void);

/* escape */
#include "escape.h"

/* get */

int init_get(server_params*, request * req);
int process_get(server_params*, request * req);
int get_dir(request * req, struct stat *statbuf);
const char* hydra_method_str( int method);

/* hash */
unsigned get_mime_hash_value(char *extension);
char *get_mime_type(const char *filename);
char *get_home_dir(char *name);
void dump_mime(void);
void dump_passwd(void);
void show_hash_stats(void);

int get_hash_value( const char* str);

#define get_alias_hash_value(x) (get_hash_value(x)%ALIAS_HASHTABLE_SIZE)
#define get_host_hash_value(x) (get_hash_value(x)%VIRTHOST_HASHTABLE_SIZE)
#define get_cgi_module_hash_value(x) (get_hash_value(x)%MODULE_HASHTABLE_SIZE)

/* log */
void open_logs(void);
void log_access(request * req);
void log_error_doc(request * req);
void boa_perror(request * req, char *message);
void log_error_time(void);
void log_error_mesg(char *file, int line, char *mesg);

/* queue */
void block_request(server_params*, request * req);
void ready_request(server_params*, request * req);
void dequeue(request ** head, request * req);
void enqueue(request ** head, request * req);

/* read */
int read_header(server_params*, request * req);
int read_body(request * req);
int write_body(request * req);

/* request */
request *new_request(server_params* params);
void get_request(server_params* params, socket_type*);
void process_requests(server_params* params, socket_type* server_s);
int process_header_end(server_params*, request * req);
int process_header_line(request * req);
int process_logline(request * req);
int process_option_line(request * req);
void add_accept_header(request * req, char *mime_type);
void free_requests(server_params* params);

/* response */
void print_ka_phrase(request * req);
void print_content_type(request * req);
void print_content_length(request * req);
void print_last_modified(request * req);
void print_http_headers(request * req);

void send_r_request_file_ok(request * req); /* 200 */
void send_r_request_cgi_status(request * req, char* status, char* desc);
void send_r_request_partial(request * req); /* 206 */
void send_r_moved_perm(request * req, char *url); /* 301 */
void send_r_moved_temp(request * req, char *url, char *more_hdr); /* 302 */
void send_r_not_modified(request * req); /* 304 */
void send_r_bad_request(request * req); /* 400 */
void send_r_unauthorized(request * req, char *name); /* 401 */
void send_r_forbidden(request * req); /* 403 */
void send_r_not_found(request * req); /* 404 */
void send_r_precondition_failed(request * req); /* 412 */
void send_r_range_unsatisfiable(request * req); /* 416 */
void send_r_error(request * req); /* 500 */
void send_r_not_implemented(request * req); /* 501 */
void send_r_bad_gateway(request * req); /* 502 */
void send_r_service_unavailable(request * req); /* 503 */
void send_r_bad_version(request * req); /* 505 */

/* cgi */
void create_common_env(void);
void clear_common_env(void);
int add_cgi_env(request * req, const char *key, const char *value, int http_prefix);
int complete_env_ssl( request* req);
int complete_env(request * req);
void create_argv(request * req, char **aargv);
int init_cgi(request * req);
int is_executable_cgi( request* req, const char* filename);

/* signals */
void init_signals(void);
void block_main_signals(void);
void unblock_main_signals(void);
void block_sigusr2(void);
void unblock_sigusr2(void);
void sighup_run(void);
void sigchld_run(void);
void sigalrm_run(void);
void sigusr1_run(void);
void sigterm_stage1_run(void);
void sigterm_stage2_run(void);

/* smp */
void smp_reinit();

/* util.c */
void clean_pathname(char *pathname);
void get_commonlog_time(char buf[30]);
void rfc822_time_buf(char *buf, time_t s);
int simple_itoa(off_t i, char buf[22]);
int boa_atoi(const char *s);
off_t boa_atoll(const char *s);
int create_etag(unsigned long int size, unsigned long int mod_time, 
   char buf[MAX_ETAG_LENGTH]);
char *escape_string(char *inp, char *buf);
int month2int(char *month);
int modified_since(time_t mtime, char *if_modified_since);
char *to_upper(char *str);
int unescape_uri(char *uri, char **query_string);
tmp_fd create_temporary_file(short want_unlink, int size);
void close_tmp_fd( tmp_fd* fds);
char * normalize_path(char *path);
int set_block_fd(int fd);
int set_nonblock_fd(int fd);
int set_cloexec_fd(int fd);
void strlower(char *s);
int check_host(char *r);
void create_url( char * buffer, int buffer_size, int secure,
   const char* hostname, int port, const char* request_uri);
void break_comma_list(char *list,
                 char *broken_list[MAX_COMMA_SEP_ELEMENTS], int *elements);
   
/* buffer */
int req_write(request * req, const char *msg);
void reset_output_buffer(request *req);
int req_write_escape_http(request * req, char *msg);
int req_write_escape_html(request * req, char *msg);
int req_flush(request * req);
char *escape_uri(char *uri);

/* timestamp */
void timestamp(void);

/* mmap_cache */
struct mmap_entry *find_mmap( int data_fd, struct stat *s);
void release_mmap( struct mmap_entry *e);
void initialize_mmap( void);
void mmap_reinit( void);
int cleanup_mmap_list(int all);

/* sublog */
int open_gen_fd(char *spec);
int process_cgi_header(request * req);

/* pipe */
int read_from_pipe(request * req);
int write_from_pipe(request * req);
int io_shuffle(request * req);

/* ip */
int bind_server(int server_s, char *ip, int port);
char *ascii_sockaddr(struct SOCKADDR *s, char *dest, int len);
int net_port(struct SOCKADDR *s);

/* select */
void* select_loop(void*);

/* HIC stuff */

void dump_cgi_action_modules( void);
void add_cgi_action(const char *executable, const char* file_type);
action_module_st *find_cgi_action_appr_module(const char *content_type, int content_type_len);

/* SSL */
void ssl_reinit();

#endif

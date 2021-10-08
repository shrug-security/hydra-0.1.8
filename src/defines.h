/*
 *  Boa, an http server
 *  Copyright (C) 1995 Paul Phillips <paulp@go2net.com>
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

/* $Id: defines.h,v 1.31 2003/01/22 07:51:50 nmav Exp $*/

#ifndef _DEFINES_H
#define _DEFINES_H

/***** Change this, or use -c on the command line to specify it *****/

#ifndef SERVER_ROOT
#define SERVER_ROOT "/etc/hydra"
#endif

/***** Change this via the CGIPath configuration value in hydra.conf *****/
#define DEFAULT_PATH     "/bin:/usr/bin:/usr/local/bin"

/***** Change this via the SinglePostLimit configuration value in hydra.conf *****/
#define SINGLE_POST_LIMIT_DEFAULT               1024 * 1024 /* 1 MB */

/***** BOA error codes for socket operations */
#define BOA_E_AGAIN -1
#define BOA_E_PIPE -2
#define BOA_E_INTR -3
#define BOA_E_UNKNOWN -255

/***** Various stuff that you may want to tweak, but probably shouldn't *****/

#define SOCKETBUF_SIZE				32*1024
#define MAX_HEADER_LENGTH			1024
#define CLIENT_STREAM_SIZE			8192
#define BUFFER_SIZE				4096

#define MODULE_HASHTABLE_SIZE			8
#define MIME_HASHTABLE_SIZE			47
#define ALIAS_HASHTABLE_SIZE                    17
#define PASSWD_HASHTABLE_SIZE		        47
#define VIRTHOST_HASHTABLE_SIZE                 20 /* You'd better increase this
                                                    * if you host several sites.
                                                    */
#define DIRECTORY_INDEX_TABLE_SIZE		30

#define REQUEST_TIMEOUT				70

#define CGI_MIME_TYPE                           "application/x-httpd-cgi"

/***** CHANGE ANYTHING BELOW THIS LINE AT YOUR OWN PERIL *****/
/***** You will probably introduce buffer overruns unless you know
       what you are doing *****/

#define MAX_SITENAME_LENGTH			256
#define MAX_LOG_LENGTH				MAX_HEADER_LENGTH + 1024
#define MAX_FILE_LENGTH				NAME_MAX
#define MAX_PATH_LENGTH				PATH_MAX
#define MAX_ETAG_LENGTH				13+1 /* does include the 
                                                  * quotes, and includes the
                                                  * terminating null character.
                                                  */

#define MAX_USER_DIR_LENGTH			60

#ifdef ACCEPT_ON
#define MAX_ACCEPT_LENGTH MAX_HEADER_LENGTH
#else
#define MAX_ACCEPT_LENGTH 0
#endif

#define CGI_VERSION				"CGI/1.1"

#ifdef USE_NCSA_CGI_ENV
# define COMMON_CGI_COUNT 5
#else
# define COMMON_CGI_COUNT 4
#endif

#define CGI_ENV_MAX     50
#define CGI_ARGC_MAX 128

/******************* RESPONSE CLASSES *****************/

#define R_INFORMATIONAL	1
#define R_SUCCESS	2
#define R_REDIRECTION	3
#define R_CLIENT_ERROR	4
#define R_SERVER_ERROR	5

/******************* RESPONSE CODES ******************/

#define R_REQUEST_OK	200
#define R_CREATED	201
#define R_ACCEPTED	202
#define R_PROVISIONAL	203       /* provisional information */
#define R_NO_CONTENT	204
#define R_REQUEST_PARTIAL	206

#define R_MULTIPLE	300          /* multiple choices */
#define R_MOVED_PERM	301
#define R_MOVED_TEMP	302
#define R_NOT_MODIFIED	304

#define R_BAD_REQUEST	400
#define R_UNAUTHORIZED	401
#define R_PAYMENT	402           /* payment required */
#define R_FORBIDDEN	403
#define R_NOT_FOUND	404
#define R_METHOD_NA	405         /* method not allowed */
#define R_NONE_ACC	406          /* none acceptable */
#define R_PROXY		407            /* proxy authentication required */
#define R_REQUEST_TO	408        /* request timeout */
#define R_CONFLICT	409
#define R_GONE		410
#define R_PRECONDITION_FAILED	412
#define R_RANGE_UNSATISFIABLE	416

#define R_ERROR		500            /* internal server error */
#define	R_NOT_IMP	501           /* not implemented */
#define	R_BAD_GATEWAY	502
#define R_SERVICE_UNAV	503      /* service unavailable */
#define	R_GATEWAY_TO	504        /* gateway timeout */
#define R_BAD_VERSION	505

/****************** METHODS *****************/

#define M_GET		1
#define M_HEAD		2
#define M_PUT		3
#define M_POST		4
#define M_DELETE	5
#define M_LINK		6
#define M_UNLINK	7

/************** REQUEST STATUS (req->status) ***************/

#define READ_HEADER             0
#define ONE_CR                  1
#define ONE_LF                  2
#define TWO_CR                  3
#define BODY_READ               4
#define BODY_WRITE              5
#define WRITE                   6
#define PIPE_READ               7
#define PIPE_WRITE              8
#define IOSHUFFLE		9
#define DONE		       10
#define DEAD                   11
#define FINISH_HANDSHAKE       12
#define SEND_ALERT             13


/************** CGI TYPE (req->is_cgi) ******************/

#define CGI                     1
#define NPH                     2
#define INDEXER_CGI             3
#define HIC_CGI			4
#define CGI_ACTION		5

/************* ALIAS TYPES (aliasp->type) ***************/

#define ALIAS			0
#define SCRIPTALIAS		1
#define REDIRECT		2

/*********** KEEPALIVE CONSTANTS (req->keepalive) *******/

#define KA_INACTIVE		0
#define KA_STOPPED     	1
#define KA_ACTIVE      	2

/********* SSL stuff */
#define MIN_MAINTENANCE_INTERVAL 1800 /* half an hour */

/********* CGI STATUS CONSTANTS (req->cgi_status) *******/
#define CGI_PARSE 1
#define CGI_BUFFER 2
#define CGI_DONE 3

/*********** MMAP_LIST CONSTANTS ************************/
#define USE_MMAP_LIST /* undefine it in constraint environments
                       * to save memory, from mmaped files.
                       */

#define MMAP_LIST_NEXT(i) (((i)+1)%max_files_cache)
#define MMAP_LIST_HASH(dev,ino,size) (((unsigned long int)ino)%max_files_cache)

/***************** Defines for break_comma_list() *************/
#define MAX_COMMA_SEP_ELEMENTS 6

/***************** HTTP HEADER STUFF ***************************/

#define TEXT_HTML "text/html; charset=ISO-8859-1"
#define CRLF "\r\n"
#define HTTP_VERSION "HTTP/1.1"

#define HTTP_0_9 0
#define HTTP_1_0 1
#define HTTP_1_1 2

/***************** HTTP/1.1 If-Match stuff ********************/

#define IF_NO_IF 0 /* unused - just to indicate that 0 is no If header */
#define IF_MATCH 1
#define IF_NONE_MATCH 2
#define IF_RANGE 4
#define IF_MODIFIED_SINCE 8

/***************** USEFUL MACROS ************************/

#ifndef INT_MAX
# define INT_MAX 2147483647L
#endif

#define HEX(x) (((x)>9)?(('a'-10)+(x)):('0'+(x)))

#ifdef USE_POLL
# define BOA_READ POLLIN|POLLPRI
# define BOA_WRITE POLLOUT
# define BOA_FD_SET(req, thefd,where) { struct pollfd *my_pfd; \
	   my_pfd = &params->pfds[params->pfd_len]; \
	   req->pollfd_id = params->pfd_len++; \
	   my_pfd->fd = thefd; \
	   my_pfd->events = where; \
	}
# define BOA_FD_ZERO( ign) /* nothing */
# define BOA_FD_CLR(req, fd, where) /* this doesn't do anything? */
#else /* SELECT */
# define BOA_READ &params->block_read_fdset
# define BOA_WRITE &params->block_write_fdset
# define BOA_FD_SET(req, fd, where) { FD_SET(fd, where); if (fd > params->max_fd) params->max_fd = fd; }
# define BOA_FD_CLR(req, fd, where) { FD_CLR(fd, where); }
# define BOA_FD_ZERO( fdset) FD_ZERO( fdset)
#endif

/******** MACROS TO CHANGE BLOCK/NON-BLOCK **************/

#define DIE(mesg) log_error_mesg(__FILE__, __LINE__, mesg), exit(1)
#define WARN(mesg) log_error_mesg(__FILE__, __LINE__, mesg)

#endif

/***************** USEFUL MACROS ************************/

#define SQUASH_KA(req) (req->keepalive=KA_STOPPED)


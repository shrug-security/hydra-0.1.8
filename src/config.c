/*
 *  Hydra, an http server
 *  Copyright (C) 1999 Larry Doolittle <ldoolitt@boa.org>
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

/* $Id: config.c,v 1.21 2006-03-09 18:11:07 nmav Exp $*/

#include "boa.h"
#include "boa_grammar.h"
#include "access.h"
#include "parse.h"

int yyparse(void);              /* Better match the output of lex */

#ifdef DEBUG
#define DBG(x) x
#else
#define DBG(x)
#endif

int server_port;
uid_t server_uid;
gid_t server_gid;
char *server_root;
char *server_name;
char *server_admin;
char *server_ip;
long int max_connections;
long int max_ssl_connections;

char * default_charset = NULL;

int max_files_cache = 256;
int max_file_size_cache = 100 * 1024;

int max_server_threads = 1;

char *server_cert;
char *server_key;
char *ca_cert = NULL;
int ssl_session_cache;
int ssl_verify = 0;
int boa_ssl = 0;
int ssl_port = 443;
int ssl_dh_bits = 1024; /* default value */
int ssl_session_timeout = 3600;
int maintenance_interval = 432000; /* every 5 days */

char *ssl_ciphers = NULL;
char *ssl_mac = NULL;
char *ssl_kx = NULL;
char *ssl_comp = NULL;
char *ssl_protocol = NULL;

char *default_type;
char *dirmaker;
char *cachedir;

char *tempdir;
int tempdir_len = 0;

char *cgi_path = NULL;
int cgi_umask = 027;
char *pid_file;

int single_post_limit = SINGLE_POST_LIMIT_DEFAULT;

int ka_timeout;
int ka_max;

/* These came from log.c */
char *error_log_name;
char *access_log_name;
char *cgi_log_name;

int use_localtime;

/* These are new */
static void c_set_user(char *v1, char* v2, char* v3, char* v4, void *t);
static void c_set_group(char *v1, char* v2, char* v3, char* v4, void *t);
static void c_set_string(char *v1, char* v2, char* v3, char* v4, void *t);
static void c_set_int(char *v1, char* v2, char* v3, char* v4, void *t);
static void c_set_longint(char *v1, char* v2, char* v3, char* v4, void *t);
static void c_set_unity(char *v1, char* v2, char* v3, char* v4, void *t);
static void c_add_type(char *v1, char* v2, char* v3, char* v4, void *t);
static void c_add_vhost(char *v1, char* v2, char* v3, char*v4, void *t);
static void c_set_documentroot(char *v1, char* v2, char* v3, char*v4, void *t);
static void c_add_alias(char *v1, char* v2, char* v3, char* v4, void *t);
static void c_add_dirindex(char *v1, char* v2, char* v3, char* v4, void *t);
static void c_add_cgi_action(char *v1, char* v2, char* v3, char* v4, void *t);
#ifdef ENABLE_ACCESS_LISTS
static void c_add_access(char *v1, char *v2, char* v3, char* v4, void *t);
#endif

/* Fakery to keep the value passed to action() a void *,
   see usage in table and c_add_alias() below */
static int script_number = SCRIPTALIAS;
static int redirect_number = REDIRECT;
static int alias_number = ALIAS;
static uid_t current_uid=0;

/* Help keep the table below compact */
#define S0A STMT_NO_ARGS
#define S1A STMT_ONE_ARG
#define S2A STMT_TWO_ARGS
#define S3A STMT_THREE_ARGS
#define S4A STMT_FOUR_ARGS

struct ccommand clist[] = {
    {"SSLVerifyClient", S1A, c_set_int, &ssl_verify},
    {"SSLCiphers", S1A, c_set_string, &ssl_ciphers},
    {"SSLKeyExchangeAlgorithms", S1A, c_set_string, &ssl_kx},
    {"SSLMACAlgorithms", S1A, c_set_string, &ssl_mac},
    {"SSLProtocols", S1A, c_set_string, &ssl_protocol},
    {"SSLCompressionMethods", S1A, c_set_string, &ssl_comp},
    {"SSLCertificate", S1A, c_set_string, &server_cert},
    {"SSLCAList", S1A, c_set_string, &ca_cert},
    {"SSLKey", S1A, c_set_string, &server_key},
    {"SSLSessionCache", S1A, c_set_int, &ssl_session_cache},
    {"SSL", S1A, c_set_int, &boa_ssl},
    {"SSLPort", S1A, c_set_int, &ssl_port},
    {"SSLDHBits", S1A, c_set_int, &ssl_dh_bits},
    {"SSLSessionTimeout", S1A, c_set_int, &ssl_session_timeout},
    {"MaintenanceInterval", S1A, c_set_int, &maintenance_interval},
    {"Threads", S1A, c_set_int, &max_server_threads},
    {"Port", S1A, c_set_int, &server_port},
    {"Listen", S1A, c_set_string, &server_ip},
    {"BackLog", S1A, c_set_int, &backlog},
    {"User", S1A, c_set_user, NULL},
    {"Group", S1A, c_set_group, NULL},
    {"ServerAdmin", S1A, c_set_string, &server_admin},
    {"ServerRoot", S1A, c_set_string, &server_root},
    {"ErrorLog", S1A, c_set_string, &error_log_name},
    {"AccessLog", S1A, c_set_string, &access_log_name},
    {"UseLocaltime", S0A, c_set_unity, &use_localtime},
    {"CgiLog", S1A, c_set_string, &cgi_log_name},
    {"VerboseCGILogs", S0A, c_set_unity, &verbose_cgi_logs},
    {"ServerName", S1A, c_set_string, &server_name},
    {"DocumentRoot", S1A, c_set_documentroot, NULL},
    {"DirectoryIndex", S1A, c_add_dirindex, NULL},
    {"DirectoryMaker", S1A, c_set_string, &dirmaker},
    {"DirectoryCache", S1A, c_set_string, &cachedir},
    {"KeepAliveMax", S1A, c_set_int, &ka_max},
    {"KeepAliveTimeout", S1A, c_set_int, &ka_timeout},
    {"MimeTypes", S1A, c_set_string, &mime_types},
    {"DefaultType", S1A, c_set_string, &default_type},
    {"DefaultCharset", S1A, c_set_string, &default_charset},
    {"AddType", S2A, c_add_type, NULL},
    {"CGIAction", S2A, c_add_cgi_action, NULL},
    {"ScriptAlias", S3A, c_add_alias, &script_number},
    {"Redirect", S3A, c_add_alias, &redirect_number},
    {"Alias", S3A, c_add_alias, &alias_number},
    {"PidFile", S1A, c_set_string, &pid_file},
    {"CGIumask", S1A, c_set_int, &cgi_umask},
    {"CGILog", S1A, c_set_string, &cgi_log_name},
/* HOST - IP - DOCUMENT_ROOT - USER_DIR */
    {"VirtualHost", S4A, c_add_vhost, NULL},
    {"SinglePostLimit", S1A, c_set_int, &single_post_limit},
    {"CGIPath", S1A, c_set_string, &cgi_path},
    {"MaxSSLConnections", S1A, c_set_longint, &max_ssl_connections},
    {"MaxConnections", S1A, c_set_longint, &max_connections},
    {"MaxFilesCache", S1A, c_set_int, &max_files_cache},
    {"MaxFileSizeCache", S1A, c_set_int, &max_file_size_cache},
#ifdef ENABLE_ACCESS_LISTS
    {"Allow", S2A, c_add_access, (void*)ACCESS_ALLOW},
    {"Deny", S2A, c_add_access, (void*)ACCESS_DENY},
#endif
};

static void c_set_user(char *v1, char* v2, char* v3, char* v4, void *t)
{
    struct passwd *passwdbuf;
    char *endptr;
    int i;

    DBG(printf("User %s = ", v1);
        )
        i = strtol(v1, &endptr, 0);
    if (*v1 != '\0' && *endptr == '\0') {
        server_uid = i;
    } else {
        passwdbuf = getpwnam(v1);
        if (!passwdbuf) {
            if (current_uid)
                return;
            fprintf(stderr, "No such user: %s\n", v1);
            exit(1);
        }
        server_uid = passwdbuf->pw_uid;
    }
    DBG(printf("%d\n", server_uid);
        )
}

static void c_set_group(char *v1, char* v2, char* v3, char* v4, void *t)
{
    struct group *groupbuf;
    char *endptr;
    int i;
    DBG(printf("Group %s = ", v1);
        )
        i = strtol(v1, &endptr, 0);
    if (*v1 != '\0' && *endptr == '\0') {
        server_gid = i;
    } else {
        groupbuf = getgrnam(v1);
        if (!groupbuf) {
            if (current_uid)
                return;
            fprintf(stderr, "No such group: %s\n", v1);
            exit(1);
        }
        server_gid = groupbuf->gr_gid;
    }
    DBG(printf("%d\n", server_gid);
        )
}

static void c_set_string(char *v1, char* v2, char* v3, char* v4, void *t)
{
    char *s;
    DBG(printf("Setting pointer %p to string %s ..", t, v1);
        )
        if (t) {
        s = *(char **) t;
        if (s)
            free(s);
        *(char **) t = strdup(v1);
        if (!*(char **) t) {
            DIE("Unable to strdup in c_set_string");
        }
        DBG(printf("done.\n");
            )
    } else {
        DBG(printf("skipped.\n");
            )
    }
}

static void c_set_documentroot(char *v1, char* v2, char* v3, char* v4, void *t)
{
    /* Add the "", which is the default virtual host */
    add_virthost("", "*", v1, "");
}

static void c_set_int(char *v1, char* v2, char* v3, char* v4, void *t)
{
    char *endptr;
    int i;
    DBG(printf("Setting pointer %p to integer string %s ..", t, v1);
        )
        if (t) {
        i = strtol(v1, &endptr, 0); /* Automatic base 10/16/8 switching */
        if (*v1 != '\0' && *endptr == '\0') {
            *(int *) t = i;
            DBG(printf(" Integer converted as %d, done\n", i);
                )
        } else {
            /* XXX should tell line number to user */
            fprintf(stderr, "Error: %s found where integer expected\n",
                    v1);
        }
    } else {
        DBG(printf("skipped.\n");
            )
    }
}

static void c_set_longint(char *v1, char* v2, char* v3, char* v4, void *t)
{
    char *endptr;
    int i;
    DBG(printf("Setting pointer %p to long integer string %s ..", t, v1);
        )
        if (t) {
        i = strtol(v1, &endptr, 0); /* Automatic base 10/16/8 switching */
        if (*v1 != '\0' && *endptr == '\0') {
            *(long int *) t = i;
            DBG(printf(" Integer converted as %d, done\n", i);
                )
        } else {
            /* XXX should tell line number to user */
            fprintf(stderr, "Error: %s found where integer expected\n",
                    v1);
        }
    } else {
        DBG(printf("skipped.\n");
            )
    }
}

static void c_set_unity(char *v1, char* v2, char* v3, char* v4, void *t)
{
    DBG(printf("Setting pointer %p to unity\n", t);
        )
        if (t)
        *(int *) t = 1;
}

static void c_add_type(char *v1, char* v2, char* v3, char* v4, void *t)
{
    add_mime_type(v2, v1);
}

static void c_add_cgi_action(char *v1, char* v2, char* v3, char* v4, void *t)
{
    add_cgi_action(v1, v2);
}

static void c_add_dirindex(char *v1, char* v2, char* v3, char* v4, void *t)
{
    add_directory_index(v1);
}

static void c_add_vhost(char *v1, char *v2, char* v3, char* v4, void *t)
{
    add_virthost(v1, v2, v3, v4);
}


static void c_add_alias(char *v1, char *v2, char* v3, char* v4, void *t)
{
    add_alias(v1, v2, v3, *(int *) t);
}

struct ccommand *lookup_keyword(char *c)
{
    struct ccommand *p;
    DBG(printf("Checking string '%s' against keyword list\n", c);
        )
        for (p = clist;
             p < clist + (sizeof (clist) / sizeof (struct ccommand)); p++) {
        if (strcmp(c, p->name) == 0)
            return p;
    }
    return NULL;
}

/*
 * Name: read_config_files
 *
 * Description: Reads config files via yyparse, then makes sure that
 * all required variables were set properly.
 */
void read_config_files(void)
{
    current_uid = getuid();
    yyin = fopen("hydra.conf", "r");

    if (!yyin) {
        fputs("Could not open hydra.conf for reading.\n", stderr);
        exit(1);
    }
    if (yyparse()) {
        fputs("Error parsing config files, exiting\n", stderr);
        exit(1);
    }

    if (!server_name) {
        struct hostent *he;
        char temp_name[100];

        if (gethostname(temp_name, 100) == -1) {
            perror("gethostname:");
            exit(1);
        }

        he = gethostbyname(temp_name);
        if (he == NULL) {
            perror("gethostbyname:");
            exit(1);
        }

        server_name = strdup(he->h_name);
        if (server_name == NULL) {
            perror("strdup:");
            exit(1);
        }
    }
    tempdir = getenv("TMPDIR");
    if (tempdir == NULL)
        tempdir = "/tmp";
    tempdir_len = strlen( tempdir);

    if (single_post_limit < 0) {
        fprintf(stderr, "Invalid value for single_post_limit: %d\n",
                single_post_limit);
        exit(1);
    }

}

#ifdef ENABLE_ACCESS_LISTS
static void c_add_access(char *v1, char *v2, char* v3, char* v4, void *t)
{
  access_add(v1, v2, (int)t);
}
#endif

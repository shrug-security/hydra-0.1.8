/*
 * Copyright (C) 2002,2003 Nikos Mavroyanopoulos
 *
 * This file is part of Hydra webserver.
 *
 * Hydra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Hydra is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "boa.h"

#ifdef ENABLE_SSL

#include "ssl.h"

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gcrypt.h>
#ifdef ENABLE_SMP
GCRY_THREAD_OPTION_PTHREAD_IMPL;

pthread_mutex_t ssl_session_cache_lock = PTHREAD_MUTEX_INITIALIZER;
#endif

extern int ssl_session_cache;
extern int ssl_session_timeout;

extern char* ssl_ciphers;
extern char* ssl_kx;
extern char* ssl_mac;
extern char* ssl_comp;
extern char* ssl_protocol;
extern int ssl_verify; /* 0 no verify, 1 request certificate, and validate
                        * if sent, 2 require certificate and validate.
                        * 3 is request one, and try to verify it. Does not fail in
                        * any case.
                        */

static void wrap_db_init(void);
static int wrap_db_store(void *dbf, gnutls_datum key, gnutls_datum data);
static gnutls_datum wrap_db_fetch(void *dbf, gnutls_datum key);
static int wrap_db_delete(void *dbf, gnutls_datum key);

static int cur = 0; /* points to the credentials structure used */
static gnutls_certificate_credentials credentials[2] = { NULL, NULL };

static int need_dh_params = 0; /* whether we need to generate DHE
 * parameters. Depend on the chosen ciphersuites.
 */
static int need_rsa_params = 0;


/* we use primes up to 1024 in this server.
 * otherwise we should add them here.
 */
extern int ssl_dh_bits;

gnutls_dh_params _dh_params[2];
gnutls_rsa_params _rsa_params[2];

static int generate_dh_primes( gnutls_dh_params* dh_params)
{
    if (gnutls_dh_params_init( dh_params) < 0) {
        log_error_time();
	fprintf(stderr, "tls: Error in dh parameter initialization\n");
	exit(1);
    }

    /* Generate Diffie Hellman parameters - for use with DHE
     * kx algorithms. These should be discarded and regenerated
     * once a day, once a week or once a month. Depends on the
     * security requirements.
     */

     if (gnutls_dh_params_generate2( *dh_params, ssl_dh_bits) < 0) {
	    log_error_time();
	    fprintf(stderr, "tls: Error in prime generation\n");
	    exit(1);
     }

     log_error_time();
     fprintf
	    (stderr,
	     "tls: Generated Diffie Hellman parameters [%d bits].\n",
	     ssl_dh_bits);

     return 0;
}

static int generate_rsa_params( gnutls_rsa_params* rsa_params)
{
    if (gnutls_rsa_params_init( rsa_params) < 0) {
	log_error_time();
	fprintf(stderr, "tls: Error in rsa parameter initialization\n");
	exit(1);
    }

    /* Generate RSA parameters - for use with RSA-export
     * cipher suites. These should be discarded and regenerated
     * once a day, once every 500 transactions etc. Depends on the
     * security requirements.
     */

    if (gnutls_rsa_params_generate2( *rsa_params, 512) < 0) {
	log_error_time();
	fprintf(stderr, "tls: Error in rsa parameter generation\n");
	exit(1);
    }

    log_error_time();
    fprintf
	(stderr, "tls: Generated temporary RSA parameters.\n");

    return 0;
}

static int protocol_priority[16];
static int kx_priority[16];
static int cipher_priority[16];
static int mac_priority[16];
static int comp_priority[16];

/* Parses a string in the form:
 * CIPHER1, CIPHER2, ... and tries to find the given algorithm.
 * This is inefficient. Returns true or false.
 */
static int parse_cs_string( const char* string, const char* algo)
{
char *broken_list[MAX_COMMA_SEP_ELEMENTS];
int broken_list_size, i;
char list[64];

	if (string == NULL || algo == NULL) return 0;
	
	if (strlen( string) > sizeof(list)-1) return 0;

	strcpy( list, string);
	
	break_comma_list( list, broken_list, &broken_list_size);
	
	for (i=0;i<broken_list_size;i++) {
  	   if (strcmp( broken_list[i], algo) == 0) {
		return 1;
           }
	}
		
	return 0;

}

/* Initializes a single SSL/TLS session. That is set the algorithm,
 * the db backend, whether to request certificates etc.
 */
gnutls_session initialize_ssl_session(void)
{
    gnutls_session state;
    
    gnutls_init(&state, GNUTLS_SERVER);

    gnutls_cipher_set_priority(state, cipher_priority);
    gnutls_compression_set_priority(state, comp_priority);
    gnutls_kx_set_priority(state, kx_priority);
    gnutls_protocol_set_priority(state, protocol_priority);
    gnutls_mac_set_priority(state, mac_priority);

    gnutls_credentials_set(state, GNUTLS_CRD_CERTIFICATE, credentials[ cur]);

    gnutls_certificate_server_set_request(state, GNUTLS_CERT_IGNORE);

    if (ssl_session_cache != 0) {
	gnutls_db_set_retrieve_function(state, wrap_db_fetch);
	gnutls_db_set_remove_function(state, wrap_db_delete);
	gnutls_db_set_store_function(state, wrap_db_store);
	gnutls_db_set_ptr(state, NULL);
    }
    gnutls_db_set_cache_expiration( state, ssl_session_timeout);

    /* gnutls_handshake_set_private_extensions( state, 1); */

    if (ssl_verify == 1 || ssl_verify == 3) {
       gnutls_certificate_server_set_request( state, GNUTLS_CERT_REQUEST);
    } else if (ssl_verify == 2) {
       gnutls_certificate_server_set_request( state, GNUTLS_CERT_REQUIRE);
    } else { /* default */
       gnutls_certificate_server_set_request(state, GNUTLS_CERT_IGNORE);
    }


    return state;
}

extern char *ca_cert;
extern char *server_cert;
extern char *server_key;

/* Initialization of gnutls' global state
 */
int initialize_ssl(void)
{
    int i;

    log_error_time();
    fprintf(stderr, "tls: Initializing GnuTLS/%s.\n", gnutls_check_version(NULL));
#ifdef ENABLE_SMP
    gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
#endif
    gnutls_global_init();

    if (gnutls_certificate_allocate_credentials( &credentials[0]) < 0) {
	log_error_time();
	fprintf(stderr, "tls: certificate allocation error\n");
	exit(1);
    }

    if (gnutls_certificate_set_x509_key_file
	( credentials[0], server_cert, server_key, GNUTLS_X509_FMT_PEM) < 0) {
	log_error_time();
	fprintf(stderr, "tls: could not find '%s' or '%s'.\n", server_cert,
		server_key);
	exit(1);
    }

    if (ca_cert != NULL && gnutls_certificate_set_x509_trust_file
	( credentials[0], ca_cert, GNUTLS_X509_FMT_PEM) < 0) {
	log_error_time();
	fprintf(stderr, "tls: could not find '%s'.\n", ca_cert);
	exit(1);
    }

    if (ssl_session_cache != 0)
	wrap_db_init();

    /* Add ciphers 
     */
    i = 0;
    if ( parse_cs_string( ssl_ciphers, "AES") != 0)
    	cipher_priority[i++] = GNUTLS_CIPHER_RIJNDAEL_128_CBC;
    if ( parse_cs_string( ssl_ciphers, "ARCFOUR-128") != 0)
    	cipher_priority[i++] = GNUTLS_CIPHER_ARCFOUR_128;
    if ( parse_cs_string( ssl_ciphers, "3DES") != 0)
    	cipher_priority[i++] = GNUTLS_CIPHER_3DES_CBC;
    if ( parse_cs_string( ssl_ciphers, "ARCFOUR-40") != 0)
    	cipher_priority[i++] = GNUTLS_CIPHER_ARCFOUR_40;
    cipher_priority[i] = 0;

    /* Add key exchange methods
     */
    i = 0;
    if ( parse_cs_string( ssl_kx, "RSA") != 0)
    	kx_priority[i++] = GNUTLS_KX_RSA;
    if ( parse_cs_string( ssl_kx, "RSA-EXPORT") != 0) {
    	kx_priority[i++] = GNUTLS_KX_RSA_EXPORT;
    	need_rsa_params = 1;
    }
    if ( parse_cs_string( ssl_kx, "DHE-RSA") != 0) {
    	kx_priority[i++] = GNUTLS_KX_DHE_RSA;
    	need_dh_params = 1; /* generate DH parameters */
    }
    if ( parse_cs_string( ssl_kx, "DHE-DSS") != 0) {
    	kx_priority[i++] = GNUTLS_KX_DHE_DSS;
    	need_dh_params = 1;
    }
    kx_priority[i] = 0;

    /* Add MAC Algorithms
     */
    i = 0;
    if ( parse_cs_string( ssl_mac, "MD5") != 0)
    	mac_priority[i++] = GNUTLS_MAC_MD5;
    if ( parse_cs_string( ssl_mac, "SHA1") != 0)
    	mac_priority[i++] = GNUTLS_MAC_SHA;
    if ( parse_cs_string( ssl_mac, "RMD160") != 0)
    	mac_priority[i++] = GNUTLS_MAC_RMD160;
    mac_priority[i] = 0;

    /* Add Compression algorithms
     */
    i = 0;
    if ( parse_cs_string( ssl_comp, "NULL") != 0)
    	comp_priority[i++] = GNUTLS_COMP_NULL;
    if ( parse_cs_string( ssl_comp, "ZLIB") != 0)
    	comp_priority[i++] = GNUTLS_COMP_ZLIB;
    if ( parse_cs_string( ssl_comp, "LZO") != 0)
    	comp_priority[i++] = GNUTLS_COMP_LZO;
    comp_priority[i] = 0;

    /* Add protocols
     */
    i = 0;
    if ( parse_cs_string( ssl_protocol, "TLS1.0") != 0)
    	protocol_priority[i++] = GNUTLS_TLS1;
    if ( parse_cs_string( ssl_protocol, "TLS1.1") != 0)
    	protocol_priority[i++] = GNUTLS_TLS1_1;
    if ( parse_cs_string( ssl_protocol, "SSL3.0") != 0)
    	protocol_priority[i++] = GNUTLS_SSL3;
    protocol_priority[i] = 0;

    /* Generate temporary parameters -- if needed.
     */
    if (need_rsa_params) {
    	generate_rsa_params( &_rsa_params[0]);
	gnutls_certificate_set_rsa_export_params(credentials[0], _rsa_params[0]);
    }

    if (need_dh_params) {
	generate_dh_primes( &_dh_params[0]);
	gnutls_certificate_set_dh_params(credentials[0], _dh_params[0]);
    }

    return 0;
}

/* This function will regenerate the SSL parameters (RSA and DH) without
 * any need for downtime.
 */

void ssl_regenerate_params(void)
{
static int already_here; /* static so the default value == 0 */
int _cur = (cur + 1) % 2;

   /* There is a rare situation where we have been here, because of
    * a SIGHUP signal, and the process receives a SIGALRM as well.
    * We try to avoid messing everything up.
    */
   if (already_here != 0) return;
   already_here = 1;

/* The hint here, is that we keep a copy of 2 certificate credentials.
 * When we come here, we free the unused copy and allocate new
 * parameters to it. Then we make the current copy to be this copy.
 *
 * We don't free the previous copy because we don't know if anyone
 * is using it. (this has to be fixed)
 */

    time(&current_time);

    if ( !credentials[_cur]) {
       if (gnutls_certificate_allocate_credentials( &credentials[ _cur]) < 0) {
 	  log_error_time();
 	  fprintf(stderr, "tls: certificate allocation error\n");
	  exit(1);
       }

       if (gnutls_certificate_set_x509_key_file
  	   ( credentials[_cur], server_cert, server_key, GNUTLS_X509_FMT_PEM) < 0) {
	   log_error_time();
	   fprintf(stderr, "tls: could not find '%s' or '%s'.", server_cert,
		server_key);
	   exit(1);
       }

       if (ca_cert!=NULL && gnutls_certificate_set_x509_trust_file
   	  ( credentials[_cur], ca_cert, GNUTLS_X509_FMT_PEM) < 0) {
   	  log_error_time();
   	  fprintf(stderr, "tls: could not find '%s'.\n", ca_cert);
   	  exit(1);
       }
    }
    
    if (need_rsa_params) {
	gnutls_rsa_params_deinit( _rsa_params[ _cur]);
	generate_rsa_params( &_rsa_params[ _cur]);
        gnutls_certificate_set_rsa_export_params(credentials[_cur], _rsa_params[ _cur]);
    }

    if (need_dh_params) {
	gnutls_dh_params_deinit( _dh_params[ _cur]);
        generate_dh_primes( &_dh_params[ _cur]);
        gnutls_certificate_set_dh_params(credentials[_cur], _dh_params[ _cur]);
    }

    cur = _cur;

    already_here = 0;
    return;
}


/* Session resuming: 
 */

#define SESSION_ID_SIZE 32
#define SESSION_DATA_SIZE 1024

typedef struct {
    char session_id[SESSION_ID_SIZE];
    int session_id_size;

    char session_data[SESSION_DATA_SIZE];
    int session_data_size;
} CACHE;

static CACHE *cache_db;
static int cache_db_ptr;

static void wrap_db_init(void)
{

    /* allocate cache_db */
    cache_db = calloc(1, ssl_session_cache * sizeof(CACHE));
}

static int wrap_db_store(void *dbf, gnutls_datum key, gnutls_datum data)
{

    if (cache_db == NULL)
	return -1;

    if (key.size > SESSION_ID_SIZE)
	return -1;
    if (data.size > SESSION_DATA_SIZE)
	return -1;

#ifdef ENABLE_SMP
    pthread_mutex_lock( &ssl_session_cache_lock);
#endif

    memcpy(cache_db[cache_db_ptr].session_id, key.data, key.size);
    cache_db[cache_db_ptr].session_id_size = key.size;

    memcpy(cache_db[cache_db_ptr].session_data, data.data, data.size);
    cache_db[cache_db_ptr].session_data_size = data.size;

    cache_db_ptr++;
    cache_db_ptr %= ssl_session_cache;

#ifdef ENABLE_SMP
    pthread_mutex_unlock( &ssl_session_cache_lock);
#endif

    return 0;
}

static gnutls_datum wrap_db_fetch(void *dbf, gnutls_datum key)
{
    gnutls_datum res = { NULL, 0 };
    int i;

    if (cache_db == NULL)
	return res;

#ifdef ENABLE_SMP
    pthread_mutex_lock( &ssl_session_cache_lock);
#endif

    for (i = 0; i < ssl_session_cache; i++) {
	if (key.size == cache_db[i].session_id_size &&
	    memcmp(key.data, cache_db[i].session_id, key.size) == 0) {

	    res.size = cache_db[i].session_data_size;

	    res.data = malloc(res.size);
	    if (res.data == NULL) {
#ifdef ENABLE_SMP
                pthread_mutex_unlock( &ssl_session_cache_lock);
#endif
		return res;
            }

	    memcpy(res.data, cache_db[i].session_data, res.size);

#ifdef ENABLE_SMP
            pthread_mutex_unlock( &ssl_session_cache_lock);
#endif
	    return res;
	}
    }

#ifdef ENABLE_SMP
    pthread_mutex_unlock( &ssl_session_cache_lock);
#endif

    return res;
}

static int wrap_db_delete(void *dbf, gnutls_datum key)
{
int i;

    if (cache_db == NULL)
	return -1;

#ifdef ENABLE_SMP
    pthread_mutex_lock( &ssl_session_cache_lock);
#endif

    for (i = 0; i < ssl_session_cache; i++) {
	if (key.size == cache_db[i].session_id_size &&
	    memcmp(key.data, cache_db[i].session_id, key.size) == 0) {

	    cache_db[i].session_id_size = 0;
	    cache_db[i].session_data_size = 0;

#ifdef ENABLE_SMP
            pthread_mutex_unlock( &ssl_session_cache_lock);
#endif

	    return 0;
	}
    }

#ifdef ENABLE_SMP
    pthread_mutex_unlock( &ssl_session_cache_lock);
#endif
    return -1;

}

void check_ssl_alert( request* req, int ret)
{
   int last_alert;

   if (ret == GNUTLS_E_WARNING_ALERT_RECEIVED || ret == GNUTLS_E_FATAL_ALERT_RECEIVED) 
   {
      last_alert = gnutls_alert_get(req->ssl_state);
      log_error_doc(req);
      fprintf(stderr, "tls: Received alert %d '%s'.\n", last_alert, gnutls_alert_get_name(last_alert));
   }
}

int finish_handshake(request * current)
{
    int retval;

    retval = gnutls_handshake(current->ssl_state);

    if (retval == GNUTLS_E_AGAIN)
	retval = -1;
    else if (retval == GNUTLS_E_INTERRUPTED)
	retval = 1;
    else if (retval < 0) {
	if (gnutls_error_is_fatal(retval) != 0) {
	    log_error_doc(current);
	    fprintf(stderr, "tls: Handshake error '%s'.\n", gnutls_strerror(retval));
	    check_ssl_alert( current, retval);

	    /* we ignore the level of the alert, since we always
	     * send fatal alerts.
	     */
	    current->alert_to_send = gnutls_error_to_alert( retval, NULL);
	    if (current->alert_to_send == GNUTLS_E_INVALID_REQUEST)
	       current->alert_to_send = GNUTLS_A_HANDSHAKE_FAILURE;

      	    current->status = SEND_ALERT;
	    retval = 1;
	} else {
	    check_ssl_alert( current, retval);
	    retval = 1;
	}
    } else if (retval == 0) {
        
        if (ssl_verify >= 1) {
           size_t size;
           int verify, ret, valid;
           char name[128];
           const gnutls_datum *cert_list;
           int cert_list_size;
           gnutls_x509_crt crt = NULL;

           ret = gnutls_x509_crt_init( &crt);
           if (ret < 0) {
               log_error_time();
               fprintf( stderr, "tls: Error in crt_init(): %s\n", gnutls_strerror(ret));
               current->alert_to_send = GNUTLS_A_INTERNAL_ERROR;
               current->status = SEND_ALERT;
               return 1;
           }

           cert_list =
  	     gnutls_certificate_get_peers(current->ssl_state, &cert_list_size);
  	      
  	   if (cert_list) {
              ret = gnutls_x509_crt_import( crt, &cert_list[0], GNUTLS_X509_FMT_DER);
	      if (ret < 0) {
                  log_error_time();
                  fprintf( stderr, "tls: Could not import X.509 certificate: %s\n", gnutls_strerror(ret));
                  current->alert_to_send = GNUTLS_A_INTERNAL_ERROR;
                  current->status = SEND_ALERT;
                  return 1;
              }
	      
	      size = sizeof(name);
	      if (gnutls_x509_crt_get_dn(crt, name, &size) < 0)
		   strcpy(name, "Unknown");
	   }


           verify = gnutls_certificate_verify_peers( current->ssl_state);
           current->certificate_verified = "NONE";

           if (cert_list == NULL) {
                  log_error_time();
                  fprintf( stderr, "tls: Peer did not send a certificate.\n");
                  if (ssl_verify == 2) {
                     current->alert_to_send = GNUTLS_A_ACCESS_DENIED;
                     current->status = SEND_ALERT;
                     return 1;
                  }
           } else { /* cert_list */
              log_error_time();
              valid = 0;
              fprintf( stderr, "tls: X.509 Certificate by '%s' is ", name);

              if (gnutls_x509_crt_get_expiration_time( crt) < current_time) {
                 fprintf(stderr, "Expired");
                 valid = 1;
              }

              if (gnutls_x509_crt_get_activation_time( crt) > current_time) {
                 if (!valid) fprintf(stderr, "Not yet activated");
                 valid = 1;
              }

              if (valid || verify & GNUTLS_CERT_INVALID || verify & GNUTLS_CERT_REVOKED) 
              {
                 current->certificate_verified = "FAILED";
                 fprintf( stderr, ", NOT trusted");
		 if (verify & GNUTLS_CERT_REVOKED)
		    fprintf( stderr, ", Revoked");
		 if (verify & GNUTLS_CERT_SIGNER_NOT_FOUND)
		    fprintf( stderr, ", Issuer not known");
		 if (verify & GNUTLS_CERT_SIGNER_NOT_CA)
		    fprintf( stderr, ", Issuer is not a CA");
		 fprintf( stderr, ".\n");

                 if (ssl_verify == 2 || ssl_verify == 1) {
     	             current->alert_to_send = GNUTLS_A_BAD_CERTIFICATE;
                     current->status = SEND_ALERT;
		     gnutls_x509_crt_deinit(crt);
                     return 1;
                 }
              } else {
                 current->certificate_verified = "SUCCESS";
                 fprintf( stderr, "trusted.\n");
              }
           }
        
           gnutls_x509_crt_deinit(crt);
        }
	retval = 1;
	current->status = READ_HEADER;
    }

    return retval;
}

int send_alert(request * current)
{
    int retval;

    retval = gnutls_alert_send( current->ssl_state, 
    	GNUTLS_AL_FATAL, current->alert_to_send);

    if (retval == GNUTLS_E_AGAIN)
	retval = -1;
    else if (retval == GNUTLS_E_INTERRUPTED)
	retval = 1;
    else if (retval <= 0) {
        retval = 0;
	current->status = DEAD;
    }
    
    return retval;
}

/* This will parse the ciphers given and set the new ciphers.
 * If required it will regenerate RSA and DHE parameters.
 */
void ssl_reinit()
{
    int i;
    
    need_dh_params = 0;
    need_rsa_params = 0;

    /* Add ciphers 
     */
    i = 0;
    if ( parse_cs_string( ssl_ciphers, "AES") != 0)
    	cipher_priority[i++] = GNUTLS_CIPHER_RIJNDAEL_128_CBC;
    if ( parse_cs_string( ssl_ciphers, "ARCFOUR-128") != 0)
    	cipher_priority[i++] = GNUTLS_CIPHER_ARCFOUR_128;
    if ( parse_cs_string( ssl_ciphers, "3DES") != 0)
    	cipher_priority[i++] = GNUTLS_CIPHER_3DES_CBC;
    if ( parse_cs_string( ssl_ciphers, "ARCFOUR-40") != 0)
    	cipher_priority[i++] = GNUTLS_CIPHER_ARCFOUR_40;
    cipher_priority[i] = 0;

    /* Add key exchange methods
     */
    i = 0;
    if ( parse_cs_string( ssl_kx, "RSA") != 0)
    	kx_priority[i++] = GNUTLS_KX_RSA;
    if ( parse_cs_string( ssl_kx, "RSA-EXPORT") != 0) {
    	kx_priority[i++] = GNUTLS_KX_RSA_EXPORT;
    	need_rsa_params = 1;
    }
    if ( parse_cs_string( ssl_kx, "DHE-RSA") != 0) {
    	kx_priority[i++] = GNUTLS_KX_DHE_RSA;
    	need_dh_params = 1; /* generate DH parameters */
    }
    if ( parse_cs_string( ssl_kx, "DHE-DSS") != 0) {
    	kx_priority[i++] = GNUTLS_KX_DHE_DSS;
    	need_dh_params = 1;
    }
    kx_priority[i] = 0;

    /* Add MAC Algorithms
     */
    i = 0;
    if ( parse_cs_string( ssl_mac, "MD5") != 0)
    	mac_priority[i++] = GNUTLS_MAC_MD5;
    if ( parse_cs_string( ssl_mac, "SHA1") != 0)
    	mac_priority[i++] = GNUTLS_MAC_SHA;
    mac_priority[i] = 0;

    /* Add Compression algorithms
     */
    i = 0;
    if ( parse_cs_string( ssl_comp, "NULL") != 0)
    	comp_priority[i++] = GNUTLS_COMP_NULL;
    if ( parse_cs_string( ssl_comp, "ZLIB") != 0)
    	comp_priority[i++] = GNUTLS_COMP_ZLIB;
    if ( parse_cs_string( ssl_comp, "LZO") != 0)
    	comp_priority[i++] = GNUTLS_COMP_LZO;
    comp_priority[i] = 0;

    /* Add protocols
     */
    i = 0;
    if ( parse_cs_string( ssl_protocol, "TLS1.0") != 0)
    	protocol_priority[i++] = GNUTLS_TLS1;
    if ( parse_cs_string( ssl_protocol, "SSL3.0") != 0)
    	protocol_priority[i++] = GNUTLS_SSL3;
    protocol_priority[i] = 0;

    
    /* Generate temporary parameters -- if needed.
     */
    ssl_regenerate_params();

    return;
}

#else /* a stub for initialize_ssl */

int initialize_ssl(void)
{
    log_error_time();
    fprintf(stderr, "tls: SSL is not available in this build. Disable SSL in Hydra's configuration file.\n");
    exit(1);
}

void ssl_reinit() {
   return;
}

#endif

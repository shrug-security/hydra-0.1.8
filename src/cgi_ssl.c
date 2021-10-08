/*
 * Copyright (C) 2002 Nikos Mavroyanopoulos
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

#include "boa.h"
#include <gnutls/x509.h>

#ifdef ENABLE_SSL
extern int ssl_verify;
#endif

/*
 * Name: add_cgi_env_ssl
 *
 * Description: Adds the required environment variables for SSL
 * secured sessions.
 *
 * Return values:
 * 0 on failure, 1 otherwise.
 */
int complete_env_ssl(request * req)
{
#ifdef ENABLE_SSL

#define CTIME "%b %d %k:%M:%S %Y %Z"

#ifndef GNUTLS_MAX_SESSION_ID
# define GNUTLS_MAX_SESSION_ID 32
#endif
   char session_id[GNUTLS_MAX_SESSION_ID];
   int session_id_length = sizeof(session_id);
   int i, ret;
   char str_session_id[(GNUTLS_MAX_SESSION_ID * 2) + 1];
   size_t size;

   if (!add_cgi_env(req, "SSL_PROTOCOL",
		    gnutls_protocol_get_name(gnutls_protocol_get_version
					     (req->ssl_state)), 0))
      return 0;

   if (!add_cgi_env(req, "HTTPS", "on", 0))
      return 0;

   if (!add_cgi_env(req, "SSL_CLIENT_VERIFY", req->certificate_verified, 0))
      return 0;

   {
      char version[20] = "GnuTLS/";
      strcat(version, gnutls_check_version(NULL));
      if (!add_cgi_env(req, "SSL_VERSION_LIBRARY", version, 0))
	 return 0;
   }

   {
      unsigned int type = 0;
      
      size = sizeof(str_session_id);
      ret = gnutls_server_name_get( req->ssl_state, str_session_id, &size, &type, 0);
            
      if (ret == 0 && type == GNUTLS_NAME_DNS)
         if (!add_cgi_env(req, "SSL_CLIENT_SERVER_NAME", str_session_id, 0))
            return 0;
   }

   if (!add_cgi_env(req, "SSL_VERSION_INTERFACE", SERVER_NAME"/"SERVER_VERSION, 0))
      return 0;

   if (!add_cgi_env(req, "SSL_CIPHER",
		    gnutls_cipher_suite_get_name(gnutls_kx_get
			 (req->ssl_state),
			 gnutls_cipher_get(req->ssl_state),
			 gnutls_mac_get(req->ssl_state)), 0))
      return 0;


   {
      char buf[22];
      char *p;
      int keysize =
	  gnutls_cipher_get_key_size(gnutls_cipher_get(req->ssl_state)) *
	  8;
      simple_itoa(keysize, buf);

      if (!add_cgi_env(req, "SSL_CIPHER_ALGKEYSIZE", buf, 0))
	 return 0;

      if (!add_cgi_env(req, "SSL_CIPHER_USEKEYSIZE", buf, 0))
	 return 0;

      if (keysize <= 40)
	 p = "true";
      else
	 p = "false";

      if (!add_cgi_env(req, "SSL_CIPHER_EXPORT", p, 0))
	 return 0;
   }

   /* generate a printable (HEX) session ID */
   if (gnutls_session_get_id
       (req->ssl_state, session_id, &session_id_length) >= 0) {
      char *p = str_session_id;

      for (i = 0; i < session_id_length; i++) {
	 *p++ = HEX((session_id[i] >> 4) & 0x0f);
	 *p++ = HEX((session_id[i]) & 0x0f);
      }
      *p = 0;

      if (!add_cgi_env(req, "SSL_SESSION_ID", str_session_id, 0))
	 return 0;
   }

   {
      const gnutls_datum *cert_list;
      char buf[512];
      int cert_list_size, ret;
      gnutls_x509_crt crt;

      buf[0] = 0;

      cert_list = gnutls_certificate_get_ours(req->ssl_state);

      /* Generate the server's DN 
       */
      if (cert_list) {
	 char serial[64];
	 char str_serial[129];
	 time_t vtime;
	 struct tm vtm;

         ret = gnutls_x509_crt_init( &crt);
         if (ret < 0) {
            return 0;
         }

         ret = gnutls_x509_crt_import( crt, &cert_list[0], GNUTLS_X509_FMT_DER);
         if (ret < 0) {
	    gnutls_x509_crt_deinit( crt);
            return 0;
         }

         size = sizeof(buf);
	 if (gnutls_x509_crt_get_dn( crt, buf, &size) < 0) strcpy(buf, "Unknown");

	 if (!add_cgi_env(req, "SSL_SERVER_S_DN", buf, 0)) {
	    gnutls_x509_crt_deinit( crt);
	    return 0;
	 }

         size = sizeof(buf);
	 if (gnutls_x509_crt_get_issuer_dn( crt, buf, &size) < 0) 
	    strcpy( buf, "Unknown");

	 if (!add_cgi_env(req, "SSL_SERVER_I_DN", buf, 0)) {
	    gnutls_x509_crt_deinit( crt);
	    return 0;
	 }

         size = sizeof(serial);
	 if (gnutls_x509_crt_get_serial( crt, serial, &size) >= 0) 
	 {
	    char *p = str_serial;

	    for (i = 0; i < size; i++) {
	       *p++ = HEX((serial[i] >> 4) & 0x0f);
	       *p++ = HEX((serial[i]) & 0x0f);
	    }
	    *p = 0;

	    if (!add_cgi_env(req, "SSL_SERVER_M_SERIAL", str_serial, 0)) {
  	       gnutls_x509_crt_deinit( crt);
	       return 0;
	    }

	 }

	 vtime =
	     gnutls_x509_crt_get_expiration_time(crt);
	 gmtime_r(&vtime, &vtm);

	 strftime(str_serial, sizeof(str_serial) - 1, CTIME, &vtm);

	 if (!add_cgi_env(req, "SSL_SERVER_V_END", str_serial, 0)) {
            gnutls_x509_crt_deinit( crt);
	    return 0;
	 }

	 vtime =
	     gnutls_x509_crt_get_activation_time(crt);
	 gmtime_r(&vtime, &vtm);

	 strftime(str_serial, sizeof(str_serial) - 1, CTIME, &vtm);

	 if (!add_cgi_env(req, "SSL_SERVER_V_START", str_serial, 0)) {
            gnutls_x509_crt_deinit( crt);
	    return 0;
	 }
	 
	 gnutls_x509_crt_deinit( crt);
      }

      if (ssl_verify >= 1) {
	 /* Read peer's certificate - if any 
	  */
	 cert_list =
	     gnutls_certificate_get_peers(req->ssl_state, &cert_list_size);

	 if (cert_list != NULL) {
	    char serial[64];
	    char str_serial[129];
	    time_t vtime;
	    struct tm vtm;

            ret = gnutls_x509_crt_init( &crt);
            if (ret < 0) {
               return 0;
            }

            ret = gnutls_x509_crt_import( crt, &cert_list[0], GNUTLS_X509_FMT_DER);
            if (ret < 0) {
  	       gnutls_x509_crt_deinit( crt);
               return 0;
            }

            size = sizeof(buf);
   	    if (gnutls_x509_crt_get_dn( crt, buf, &size) < 0) 
   	       strcpy( buf, "Unknown");
	    
	    if (!add_cgi_env(req, "SSL_CLIENT_S_DN", buf, 0)) {
	       gnutls_x509_crt_deinit( crt);
	       return 0;
	    }

            size = sizeof(buf);
   	    if (gnutls_x509_crt_get_issuer_dn( crt, buf, &size) < 0) 
   	       strcpy( buf, "Unknown");
	    
	    if (!add_cgi_env(req, "SSL_CLIENT_I_DN", buf, 0)) {
	       gnutls_x509_crt_deinit( crt);
	       return 0;
	    }

            /* Extract serial and expiration time.
             */
            size = sizeof( serial);
	    if (gnutls_x509_crt_get_serial( crt, serial, &size) >= 0) {
	       char *p = str_serial;

	       for (i = 0; i < size; i++) {
		  *p++ = HEX((serial[i] >> 4) & 0x0f);
		  *p++ = HEX((serial[i]) & 0x0f);
	       }
	       *p = 0;

	       if (!add_cgi_env(req, "SSL_CLIENT_M_SERIAL", str_serial, 0)) {
		  gnutls_x509_crt_deinit( crt);
		  return 0;
	       }

	    }

	    vtime =
		gnutls_x509_crt_get_expiration_time(crt);
	    gmtime_r(&vtime, &vtm);

	    strftime(str_serial, sizeof(str_serial) - 1, CTIME, &vtm);

	    if (!add_cgi_env(req, "SSL_CLIENT_V_END", str_serial, 0)) {
	       gnutls_x509_crt_deinit( crt);
	       return 0;
	    }

	    vtime = gnutls_x509_crt_get_activation_time(crt);
	    gmtime_r(&vtime, &vtm);

	    strftime(str_serial, sizeof(str_serial) - 1, CTIME, &vtm);

	    if (!add_cgi_env(req, "SSL_CLIENT_V_START", str_serial, 0)) {
	       gnutls_x509_crt_deinit( crt);
	       return 0;
	    }
	    
	    gnutls_x509_crt_deinit( crt);

	 }
      }

   }

   return 1;
#else
   return 1;
#endif
}

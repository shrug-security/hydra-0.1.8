/*
 *  Hydra, an http server
 *  Copyright (C) 1995 Paul Phillips <paulp@go2net.com>
 *  Some changes Copyright (C) 1996 Larry Doolittle <ldoolitt@boa.org>
 *  Some changes Copyright (C) 1996-99 Jon Nelson <jnelson@boa.org>
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

/* $Id: response.c,v 1.17 2003/01/22 07:51:50 nmav Exp $*/

#include "boa.h"

void print_content_type(request * req)
{
char * mime_type = get_mime_type(req->request_uri);

    if (mime_type != NULL) {
       req_write(req, "Content-Type: ");
       req_write(req, mime_type);
       if (default_charset != NULL && 
          strncasecmp( mime_type, "text", 4)==0) {

          /* add default charset */
          req_write( req, "; charset=");
          req_write( req, default_charset);
       }
       req_write(req, "\r\n");
    }
}

void print_content_length(request * req)
{
char buf[22];

    simple_itoa( (req->range_stop)-(req->range_start), buf);
    req_write(req, "Content-Length: ");
    req_write(req, buf);
    req_write(req, "\r\n");
}

void print_content_range(request * req)
{
char start[22];
char stop[22];
char total[22];
char buf[22*3 + 5];

    req_write(req, "Content-Range: bytes ");

    simple_itoa( req->range_stop, stop);
    simple_itoa( req->range_start, start);
    simple_itoa( req->filesize, total);
    
    sprintf( buf, "%s-%s/%s\r\n", start, stop, total);
    req_write(req, buf);
}

void print_last_modified(request * req)
{
    char lm[] = "Last-Modified: "
        "                             " "\r\n";
    rfc822_time_buf(lm + 15, req->last_modified);
    req_write(req, lm);
}

void print_etag(request * req)
{
char buffer[sizeof("ETag: \r\n") + MAX_ETAG_LENGTH + 1] = "ETag: ";
int len;

    len = 6; /* after "Etag: " */
    len += create_etag( req->filesize, req->last_modified, &buffer[len]);
    memcpy( &buffer[len], "\r\n\0", 3);

    req_write(req, buffer);
}

void print_ka_phrase(request * req)
{

    if (req->kacount > 0 &&
        req->keepalive == KA_ACTIVE && req->response_status < 500) {
        char buf[22];
        req_write(req, "Connection: Keep-Alive\r\nKeep-Alive: timeout=");
        simple_itoa(ka_timeout, buf);
        req_write(req, buf);
        req_write(req, ", max=");
        simple_itoa(req->kacount, buf);
        req_write(req, buf);
        req_write(req, "\r\n");
    } else
        req_write(req, "Connection: close\r\n");
}

void print_http_headers(request * req)
{
    char date_stuff[] = "Date: "
        "                             "
        "\r\n";
        
    rfc822_time_buf(date_stuff + 6, 0);

    req_write(req, date_stuff);

    if (!req->secure)
	req_write(req, boa_version);
    else
	req_write(req, boa_tls_version);

    req_write(req, "Accept-Ranges: bytes\r\n");
    print_ka_phrase(req);
}

/* The routines above are only called by the routines below.
 * The rest of Hydra only enters through the routines below.
 */

/* R_REQUEST_OK: 200 */
void send_r_request_file_ok(request * req)
{
    req->response_status = R_REQUEST_OK;
    if (req->http_version==HTTP_0_9)
        return;

    req_write(req, HTTP_VERSION" 200 OK\r\n");
    print_http_headers(req);

    if (!req->is_cgi) {
        print_content_length(req);
        print_last_modified(req);
        print_etag(req);
        print_content_type(req);
        req_write(req, "\r\n");
    }
}

void send_r_request_cgi_status(request * req, char* status, char* desc)
{
    req->response_status = R_REQUEST_OK;
    if (req->http_version==HTTP_0_9)
        return;

    req_write(req, HTTP_VERSION" ");
    req_write(req, status);
    req_write(req, " ");
    req_write(req, desc);
    req_write(req, "\r\n");

    if (!strcmp(status, "200")) print_http_headers(req);

}

/* R_REQUEST_PARTIAL: 206 */
void send_r_request_partial(request * req)
{
    req->response_status = R_REQUEST_PARTIAL;
    if (req->http_version==HTTP_0_9)
        return;

    req_write(req, HTTP_VERSION" 206 Partial content\r\n");
    print_http_headers(req);

    if (!req->is_cgi) {
        print_content_length(req);
        print_content_range(req);
        print_last_modified(req);
        print_content_type(req);
        req_write(req, "\r\n");
    }
}

/* R_MOVED_PERM: 301 */
void send_r_moved_perm(request * req, char *url)
{
    SQUASH_KA(req);
    req->response_status = R_MOVED_PERM;
    if (req->http_version > HTTP_0_9) {
        req_write(req, HTTP_VERSION" 301 Moved Permanently\r\n");
        print_http_headers(req);
        req_write(req, "Content-Type: " TEXT_HTML "\r\n");

        req_write(req, "Location: ");
        req_write_escape_http(req, url);
        req_write(req, "\r\n\r\n");
    }
    if (req->method != M_HEAD) {
        req_write(req,
                  "<HTML><HEAD><TITLE>301 Moved Permanently</TITLE></HEAD>\n"
                  "<BODY>\n<H1>301 Moved</H1>The document has moved\n"
                  "<A HREF=\"");
        req_write_escape_html(req, url);
        req_write(req, "\">here</A>.\n</BODY></HTML>\n");
    }
    req_flush(req);
}

/* R_MOVED_TEMP: 302 */
void send_r_moved_temp(request * req, char *url, char *more_hdr)
{
    SQUASH_KA(req);
    req->response_status = R_MOVED_TEMP;
    if (req->http_version > HTTP_0_9) {
        req_write(req, HTTP_VERSION" 302 Moved Temporarily\r\n");
        print_http_headers(req);
        req_write(req, "Content-Type: " TEXT_HTML "\r\n");

        req_write(req, "Location: ");
        req_write_escape_http(req, url);
        req_write(req, "\r\n");
        req_write(req, more_hdr);
        req_write(req, "\r\n\r\n");
    }
    if (req->method != M_HEAD) {
        req_write(req,
                  "<HTML><HEAD><TITLE>302 Moved Temporarily</TITLE></HEAD>\n"
                  "<BODY>\n<H1>302 Moved</H1>The document has moved\n"
                  "<A HREF=\"");
        req_write_escape_html(req, url);
        req_write(req, "\">here</A>.\n</BODY></HTML>\n");
    }
    req_flush(req);
}

/* R_NOT_MODIFIED: 304 */
void send_r_not_modified(request * req)
{
    SQUASH_KA(req);
    req->response_status = R_NOT_MODIFIED;
    req_write(req, HTTP_VERSION" 304 Not Modified\r\n");
    print_http_headers(req);
    print_content_type(req);
    print_etag(req);
    req_write(req, "\r\n");
    req_flush(req);
}

/* R_BAD_REQUEST: 400 */
void send_r_bad_request(request * req)
{
    SQUASH_KA(req);
    req->response_status = R_BAD_REQUEST;
    if (req->http_version > HTTP_0_9) {
        req_write(req, HTTP_VERSION" 400 Bad Request\r\n");
        print_http_headers(req);
        req_write(req, "Content-Type: " TEXT_HTML "\r\n\r\n"); /* terminate header */
    }
    if (req->method != M_HEAD)
        req_write(req,
                  "<HTML><HEAD><TITLE>400 Bad Request</TITLE></HEAD>\n"
                  "<BODY><H1>400 Bad Request</H1>\nYour client has issued "
                  "a malformed or illegal request.\n</BODY></HTML>\n");
    req_flush(req);
}

/* R_UNAUTHORIZED: 401 */
void send_r_unauthorized(request * req, char *realm_name)
{
    SQUASH_KA(req);
    req->response_status = R_UNAUTHORIZED;
    if (req->http_version > HTTP_0_9) {
        req_write(req, HTTP_VERSION" 401 Unauthorized\r\n");
        print_http_headers(req);
        req_write(req, "WWW-Authenticate: Basic realm=\"");
        req_write(req, realm_name);
        req_write(req, "\"\r\n");
        req_write(req, "Content-Type: " TEXT_HTML "\r\n\r\n"); /* terminate header */
    }
    if (req->method != M_HEAD) {
        req_write(req,
                  "<HTML><HEAD><TITLE>401 Unauthorized</TITLE></HEAD>\n"
                  "<BODY><H1>401 Unauthorized</H1>\nYour client does not "
                  "have permission to get URL ");
        req_write_escape_html(req, req->request_uri);
        req_write(req, " from this server.\n</BODY></HTML>\n");
    }
    req_flush(req);
}

/* R_FORBIDDEN: 403 */
void send_r_forbidden(request * req)
{
    SQUASH_KA(req);
    req->response_status = R_FORBIDDEN;
    if (req->http_version > HTTP_0_9) {
        req_write(req, HTTP_VERSION" 403 Forbidden\r\n");
        print_http_headers(req);
        req_write(req, "Content-Type: " TEXT_HTML "\r\n\r\n"); /* terminate header */
    }
    if (req->method != M_HEAD) {
        req_write(req, "<HTML><HEAD><TITLE>403 Forbidden</TITLE></HEAD>\n"
                  "<BODY><H1>403 Forbidden</H1>\nYour client does not "
                  "have permission to get URL ");
        req_write_escape_html(req, req->request_uri);
        req_write(req, " from this server.\n</BODY></HTML>\n");
    }
    req_flush(req);
}

/* R_NOT_FOUND: 404 */
void send_r_not_found(request * req)
{
    SQUASH_KA(req);
    req->response_status = R_NOT_FOUND;
    if (req->http_version > HTTP_0_9) {
        req_write(req, HTTP_VERSION" 404 Not Found\r\n");
        print_http_headers(req);
        req_write(req, "Content-Type: " TEXT_HTML "\r\n\r\n"); /* terminate header */
    }
    if (req->method != M_HEAD) {
        req_write(req, "<HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD>\n"
                  "<BODY><H1>404 Not Found</H1>\nThe requested URL ");
        req_write_escape_html(req, req->request_uri);
        req_write(req, " was not found on this server.\n</BODY></HTML>\n");
    }
    req_flush(req);
}

/* R_PRECONDITION_FAILED: 412 */
void send_r_precondition_failed(request * req)
{
    req->response_status = R_PRECONDITION_FAILED;
    if (req->http_version==HTTP_0_9)
        return;

    if (req->http_version > HTTP_0_9) {
        req_write(req, HTTP_VERSION" 412 Precondition Failed\r\n");
        print_http_headers(req);
        req_write(req, "Content-Type: " TEXT_HTML "\r\n\r\n"); /* terminate header */
    }
    if (req->method != M_HEAD) {
        req_write(req, "<HTML><HEAD><TITLE>412 Precondition Failed</TITLE></HEAD>\n"
                  "<BODY><H1>412 Precondition failed</H1>\n");

        req_write(req, "</BODY></HTML>\n");
    }
    req_flush(req);
}

/* R_RANGE_UNSATISFIABLE: 416 */
void send_r_range_unsatisfiable(request * req)
{
    req->response_status = R_RANGE_UNSATISFIABLE;
    if (req->http_version==HTTP_0_9)
        return;

    if (req->http_version > HTTP_0_9) {
        req_write(req, HTTP_VERSION" 416 Range Not Satisfiable\r\n");
        print_http_headers(req);
        req_write(req, "Content-Type: " TEXT_HTML "\r\n\r\n"); /* terminate header */
    }
    if (req->method != M_HEAD) {
        char int1[22], int2[22];
        char range[45];
        req_write(req, "<HTML><HEAD><TITLE>416 Range Not Satisfiable</TITLE></HEAD>\n"
                  "<BODY><H1>416 Range Not Satisfiable</H1>\nThe requested range URL ");
        req_write_escape_html(req, req->request_uri);
        req_write( req, " had illegal range");

        if (simple_itoa( req->range_start, int1) > 0 &&
           simple_itoa( req->range_stop, int2) > 0) {
           sprintf( range, "(%s-%s)", int1, int2);
           req_write(req, range);
        }
        req_write(req, ".\n</BODY></HTML>\n");
    }
    req_flush(req);
}

/* R_ERROR: 500 */
void send_r_error(request * req)
{
    SQUASH_KA(req);
    req->response_status = R_ERROR;
    if (req->http_version > HTTP_0_9) {
        req_write(req, HTTP_VERSION" 500 Server Error\r\n");
        print_http_headers(req);
        req_write(req, "Content-Type: " TEXT_HTML "\r\n\r\n"); /* terminate header */
    }
    if (req->method != M_HEAD) {
        req_write(req,
                  "<HTML><HEAD><TITLE>500 Server Error</TITLE></HEAD>\n"
                  "<BODY><H1>500 Server Error</H1>\nThe server encountered "
                  "an internal error and could not complete your request.\n"
                  "</BODY></HTML>\n");
    }
    req_flush(req);
}

/* R_NOT_IMP: 501 */
void send_r_not_implemented(request * req)
{
    SQUASH_KA(req);
    req->response_status = R_NOT_IMP;
    if (req->http_version > HTTP_0_9) {
        req_write(req, HTTP_VERSION" 501 Not Implemented\r\n");
        print_http_headers(req);
        req_write(req, "Content-Type: " TEXT_HTML "\r\n\r\n"); /* terminate header */
    }
    if (req->method != M_HEAD) {
        req_write(req,
                  "<HTML><HEAD><TITLE>501 Not Implemented</TITLE></HEAD>\n"
                  "<BODY><H1>501 Not Implemented</H1>\nThis is not "
                  "supported in Hydra.\n</BODY></HTML>\n");
    }
    req_flush(req);
}

/* R_BAD_GATEWAY: 502 */
void send_r_bad_gateway(request * req)
{
    SQUASH_KA(req);
    req->response_status = R_BAD_GATEWAY;
    if (req->http_version > HTTP_0_9) {
        req_write(req, HTTP_VERSION" 502 Bad Gateway" CRLF);
        print_http_headers(req);
        req_write(req, "Content-Type: " TEXT_HTML CRLF CRLF); /* terminate header */
    }
    if (req->method != M_HEAD) {
        req_write(req,
                  "<HTML><HEAD><TITLE>502 Bad Gateway</TITLE></HEAD>\n"
                  "<BODY><H1>502 Bad Gateway</H1>\nThe CGI was "
                  "not CGI/1.1 compliant.\n" "</BODY></HTML>\n");
    }
    req_flush(req);
}

/* R_SERVICE_UNAVAILABLE: 503 */
void send_r_service_unavailable(request * req) /* 503 */
{
    static const char body[] =
        "<HTML><HEAD><TITLE>503 Service Unavailable</TITLE></HEAD>\n"
        "<BODY><H1>503 Service Unavailable</H1>\n"
        "There are too many connections in use right now.\r\n"
        "Please try again later.\r\n</BODY></HTML>\n";
    static int _body_len;
    static char body_len[22];

    if (!_body_len)
        _body_len = strlen(body);
    if (!body_len[0])
        simple_itoa( _body_len, body_len);

    SQUASH_KA(req);
    req->response_status = R_SERVICE_UNAV;
    if (req->http_version > HTTP_0_9) {
        req_write(req, HTTP_VERSION" 503 Service Unavailable\r\n");
        print_http_headers(req);
        if (body_len) {
            req_write(req, "Content-Length: ");
            req_write(req, body_len);
            req_write(req, "\r\n");
        }
        req_write(req, "Content-Type: " TEXT_HTML "\r\n\r\n"); /* terminate header
                                                               */
    }
    if (req->method != M_HEAD) {
        req_write(req, body);
    }
    req_flush(req);
}


/* R_NOT_IMP: 505 */
void send_r_bad_version(request * req)
{
    SQUASH_KA(req);
    req->response_status = R_BAD_VERSION;
    if (req->http_version > HTTP_0_9) {
        req_write(req, HTTP_VERSION" 505 HTTP Version Not Supported\r\n");
        print_http_headers(req);
        req_write(req, "Content-Type: " TEXT_HTML "\r\n\r\n"); /* terminate header */
    }
    if (req->method != M_HEAD) {
        req_write(req,
                  "<HTML><HEAD><TITLE>505 HTTP Version Not Supported</TITLE></HEAD>\n"
                  "<BODY><H1>505 HTTP Version Not Supported</H1>\nHTTP versions "
                  "other than 0.9 and 1.0 "
                  "are not supported in Hydra.\n<p><p>Version encountered: ");
        req_write(req, req->http_version_str);
        req_write(req, "<p><p></BODY></HTML>\n");
    }
    req_flush(req);
}

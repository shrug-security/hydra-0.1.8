/*
 *  Hydra, an http server
 *  Copyright (C) 1995 Paul Phillips <paulp@go2net.com>
 *  Some changes Copyright (C) 1996,97 Larry Doolittle <ldoolitt@boa.org>
 *  Some changes Copyright (C) 1996 Charles F. Randall <crandall@goldsys.com>
 *  Some changes Copyright (C) 1996-99 Jon Nelson <jnelson@boa.org>
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

/* $Id: util.c,v 1.21 2003/01/26 11:25:39 nmav Exp $ */

#include "boa.h"

#define HEX_TO_DECIMAL(char1, char2)	\
    (((char1 >= 'A') ? (((char1 & 0xdf) - 'A') + 10) : (char1 - '0')) * 16) + \
    (((char2 >= 'A') ? (((char2 & 0xdf) - 'A') + 10) : (char2 - '0')))

const char month_tab[48] =
    "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec ";
const char day_tab[] = "Sun,Mon,Tue,Wed,Thu,Fri,Sat,";

/*
 * Name: clean_pathname
 *
 * Description: Replaces unsafe/incorrect instances of:
 *  //[...] with /
 *  /./ with /
 *  /../ with / (technically not what we want, but browsers should deal
 *   with this, not servers)
 */

void clean_pathname(char *pathname)
{
   char *cleanpath, c;

   cleanpath = pathname;
   while ((c = *pathname++)) {
      if (c == '/') {
	 while (1) {
	    if (*pathname == '/')
	       pathname++;
	    else if (*pathname == '.' && *(pathname + 1) == '/')
	       pathname += 2;
	    else if (*pathname == '.' && *(pathname + 1) == '.' &&
		     *(pathname + 2) == '/') {
	       pathname += 3;
	    } else
	       break;
	 }
	 c = '/';
      }
      *cleanpath++ = c;
   }

   *cleanpath = '\0';
}

/*
 * Name: get_commonlog_time
 *
 * Description: Returns the current time in common log format in a static
 * char buffer.
 *
 * commonlog time is exactly 25 characters long
 * because this is only used in logging, we add " [" before and "] " after
 * making 29 characters
 * "[27/Feb/1998:20:20:04 +0000] "
 *
 * Constrast with rfc822 time:
 * "Sun, 06 Nov 1994 08:49:37 GMT"
 *
 * Altered 10 Jan 2000 by Jon Nelson ala Drew Streib for non UTC logging
 *
 */

void get_commonlog_time(char buf[30])
{
   struct tm *t;
   char *p;
   unsigned int a;
   int time_offset;

   if (use_localtime) {
      t = localtime(&current_time);
      time_offset = TIMEZONE_OFFSET(t);
   } else {
      t = gmtime(&current_time);
      time_offset = 0;
   }

   p = buf + 29;
   *p-- = '\0';
   *p-- = ' ';
   *p-- = ']';
   a = abs(time_offset / 60);
   *p-- = '0' + a % 10;
   a /= 10;
   *p-- = '0' + a % 6;
   a /= 6;
   *p-- = '0' + a % 10;
   *p-- = '0' + a / 10;
   *p-- = (time_offset >= 0) ? '+' : '-';
   *p-- = ' ';

   a = t->tm_sec;
   *p-- = '0' + a % 10;
   *p-- = '0' + a / 10;
   *p-- = ':';
   a = t->tm_min;
   *p-- = '0' + a % 10;
   *p-- = '0' + a / 10;
   *p-- = ':';
   a = t->tm_hour;
   *p-- = '0' + a % 10;
   *p-- = '0' + a / 10;
   *p-- = ':';
   a = 1900 + t->tm_year;
   while (a) {
      *p-- = '0' + a % 10;
      a /= 10;
   }
   /* p points to an unused spot */
   *p-- = '/';
   p -= 2;
   memcpy(p--, month_tab + 4 * (t->tm_mon), 3);
   *p-- = '/';
   a = t->tm_mday;
   *p-- = '0' + a % 10;
   *p-- = '0' + a / 10;
   *p = '[';
   return;			/* should be same as returning buf */
}

/*
 * Name: month2int
 *
 * Description: Turns a three letter month into a 0-11 int
 *
 * Note: This function is from wn-v1.07 -- it's clever and fast
 */

int month2int(char *monthname)
{
   switch (*monthname) {
   case 'A':
      return (*++monthname == 'p' ? 3 : 7);
   case 'D':
      return (11);
   case 'F':
      return (1);
   case 'J':
      if (*++monthname == 'a')
	 return (0);
      return (*++monthname == 'n' ? 5 : 6);
   case 'M':
      return (*(monthname + 2) == 'r' ? 2 : 4);
   case 'N':
      return (10);
   case 'O':
      return (9);
   case 'S':
      return (8);
   default:
      return (-1);
   }
}

/*
 * Name: modified_since
 * Description: Decides whether a file's mtime is newer than the
 * If-Modified-Since header of a request.
 *

 Sun, 06 Nov 1994 08:49:37 GMT    ; RFC 822, updated by RFC 1123
 Sunday, 06-Nov-94 08:49:37 GMT   ; RFC 850, obsoleted by RFC 1036
 Sun Nov  6 08:49:37 1994         ; ANSI C's asctime() format
 31 September 2000 23:59:59 GMT   ; non-standard

 * RETURN VALUES:
 *  0: File has not been modified since specified time.
 *  1: File has been.
 * -1: Error!
 */

int modified_since(time_t mtime, char *if_modified_since)
{
   struct tm *file_gmt;
   char *ims_info;
   char monthname[10 + 1];
   int day, month, year, hour, minute, second;
   int comp;

   ims_info = if_modified_since;
   while (*ims_info != ' ' && *ims_info != '\0')
      ++ims_info;
   if (*ims_info != ' ')
      return -1;

   /* the pre-space in the third scanf skips whitespace for the string */
   if (sscanf(ims_info, "%d %3s %d %d:%d:%d GMT",	/* RFC 1123 */
	      &day, monthname, &year, &hour, &minute, &second) == 6);
   else if (sscanf(ims_info, "%d-%3s-%d %d:%d:%d GMT",	/* RFC 1036 */
		   &day, monthname, &year, &hour, &minute, &second) == 6)
      year += 1900;
   else if (sscanf(ims_info, " %3s %d %d:%d:%d %d",	/* asctime() format */
		   monthname, &day, &hour, &minute, &second, &year) == 6);
   /*  allow this non-standard date format: 31 September 2000 23:59:59 GMT */
   /* NOTE: Use if_modified_since here, because the date *starts*
    *       with the day, versus a throwaway item
    */
   else if (sscanf(if_modified_since, "%d %10s %d %d:%d:%d GMT",
		   &day, monthname, &year, &hour, &minute, &second) == 6);
   else {
      log_error_time();
      fprintf(stderr, "Error in %s, line %d: Unable to sscanf \"%s\"\n",
	      __FILE__, __LINE__, ims_info);
      return -1;		/* error */
   }

   file_gmt = gmtime(&mtime);
   month = month2int(monthname);

   /* Go through from years to seconds -- if they are ever unequal,
      we know which one is newer and can return */

   if ((comp = 1900 + file_gmt->tm_year - year))
      return (comp > 0);
   if ((comp = file_gmt->tm_mon - month))
      return (comp > 0);
   if ((comp = file_gmt->tm_mday - day))
      return (comp > 0);
   if ((comp = file_gmt->tm_hour - hour))
      return (comp > 0);
   if ((comp = file_gmt->tm_min - minute))
      return (comp > 0);
   if ((comp = file_gmt->tm_sec - second))
      return (comp > 0);

   return 0;			/* this person must really be into the latest/greatest */
}


/*
 * Name: to_upper
 *
 * Description: Turns a string into all upper case (for HTTP_ header forming)
 * AND changes - into _
 */

char *to_upper(char *str)
{
   char *start = str;

   while (*str) {
      if (*str == '-')
	 *str = '_';
      else
	 *str = toupper(*str);

      str++;
   }

   return start;
}

/*
 * Name: unescape_uri
 *
 * Description: Decodes a uri, changing %xx encodings with the actual
 * character.  The query_string should already be gone.
 *
 * Return values:
 *  1: success
 *  0: illegal string
 */

int unescape_uri(char *uri, char **query_string)
{
   char c, d;
   char *uri_old;

   uri_old = uri;

   while ((c = *uri_old)) {
      if (c == '%') {
	 uri_old++;
	 if ((c = *uri_old++) && (d = *uri_old++))
	    *uri++ = HEX_TO_DECIMAL(c, d);
	 else
	    return 0;		/* NULL in chars to be decoded */
      } else if (c == '?') {	/* query string */
	 if (query_string)
	    *query_string = ++uri_old;
	 /* stop here */
	 *uri = '\0';
	 return (1);
	 break;
      } else if (c == '#') {	/* fragment */
	 /* legal part of URL, but we do *not* care.
	  * However, we still have to look for the query string */
	 if (query_string) {
	    ++uri_old;
	    while ((c = *uri_old)) {
	       if (c == '?') {
		  *query_string = ++uri_old;
		  break;
	       }
	       ++uri_old;
	    }
	 }
	 break;
      } else {
	 *uri++ = c;
	 uri_old++;
      }
   }

   *uri = '\0';
   return 1;
}

/* rfc822 (1123) time is exactly 29 characters long
 * "Sun, 06 Nov 1994 08:49:37 GMT"
 */

void rfc822_time_buf(char *buf, time_t s)
{
   struct tm *t;
   char *p;
   unsigned int a;

   if (!s) {
      t = gmtime(&current_time);
   } else
      t = gmtime(&s);

   p = buf + 28;
   /* p points to the last char in the buf */

   p -= 3;
   /* p points to where the ' ' will go */
   memcpy(p--, " GMT", 4);

   a = t->tm_sec;
   *p-- = '0' + a % 10;
   *p-- = '0' + a / 10;
   *p-- = ':';
   a = t->tm_min;
   *p-- = '0' + a % 10;
   *p-- = '0' + a / 10;
   *p-- = ':';
   a = t->tm_hour;
   *p-- = '0' + a % 10;
   *p-- = '0' + a / 10;
   *p-- = ' ';
   a = 1900 + t->tm_year;
   while (a) {
      *p-- = '0' + a % 10;
      a /= 10;
   }
   /* p points to an unused spot to where the space will go */
   p -= 3;
   /* p points to where the first char of the month will go */
   memcpy(p--, month_tab + 4 * (t->tm_mon), 4);
   *p-- = ' ';
   a = t->tm_mday;
   *p-- = '0' + a % 10;
   *p-- = '0' + a / 10;
   *p-- = ' ';
   p -= 3;
   memcpy(p, day_tab + t->tm_wday * 4, 4);
}

/* Converts an integer to a string and
 * returns the number of digits. Does not accept negative
 * values.
 */
int simple_itoa(off_t i, char buf[22])
{
   /* 21 digits plus null terminator, good for 64-bit or smaller ints
    * for bigger ints, use a bigger buffer!
    *
    * 4294967295 is, incidentally, MAX_UINT (on 32bit systems at this time)
    * and is 10 bytes long
    */
   char *p = &buf[21];
   int digits = 1;		/* include null char */

   if (i < 0) {
      buf[0] = 0;
      return 0;
   }

   *p-- = '\0';
   do {
      digits++;
      *p-- = '0' + i % 10;
      i /= 10;
   } while (i > 0);

   p++;
   if (p != buf)
      memmove(buf, p, digits);

   return digits - 1;
}

/* Generates an Etag, by using the file size, and the modification time
 */
int create_etag(unsigned long int size, unsigned long int mod_time,
		char etag[MAX_ETAG_LENGTH])
{
   char buf[22];
   int len, len2;

   etag[0] = '\"';
   len = 1;

   len2 = simple_itoa(size % 100000, buf);	/* up to 5 digits */
   memcpy(&etag[len], buf, len2);
   len += len2;

   etag[len++] = '-';
   len2 = simple_itoa(mod_time % 100000, buf);	/* also 5 digits */
   memcpy(&etag[len], buf, len2);
   len += len2;

   etag[len++] = '\"';
   etag[len] = 0;		/* etag is null terminated */

   return len;
}


/* I don't "do" negative conversions
 * Therefore, -1 indicates error
 */

int boa_atoi(const char *s)
{
   int retval;
   char reconv[22];

   if (!isdigit(*s))
      return -1;

   retval = atoi(s);
   if (retval < 0)
      return -1;

   simple_itoa(retval, reconv);
   if (memcmp(s, reconv, strlen(s)) != 0) {
      return -1;
   }
   return retval;
}

off_t boa_atoll(const char *s)
{
   long int retval;
   char reconv[22];

   if (!isdigit(*s))
      return -1;

#ifdef HAVE_ATOLL
   retval = atoll(s);
#else
   retval = atol(s);
#endif
   if (retval < 0)
      return -1;

   simple_itoa(retval, reconv);
   if (memcmp(s, reconv, strlen(s)) != 0) {
      return -1;
   }
   return retval;
}

#define TEMP_FILE_TEMPLATE "/hydra.temp.XXXXXX"
#define TEMP_FILE_TEMPLATE_LEN sizeof(TEMP_FILE_TEMPLATE)-1

void close_tmp_fd(tmp_fd * fds)
{
   if (fds->pipe) {
      if (fds->fds[1] != -1)
	 close(fds->fds[1]);
   }

   if (fds->fds[0] != -1)
      close(fds->fds[0]);

   fds->fds[0] = fds->fds[1] = -1;

}

const static tmp_fd EMPTY_FDS = { {-1, -1}, 0 };

/* returns -1 on error */
/* size holds the number of data that will be written to
 * the temporary file.
 */
tmp_fd create_temporary_file(short want_unlink, int size)
{
   char boa_tempfile[MAX_PATH_LENGTH + 1];
   tmp_fd fd;
   int total_len;

   fd.pipe = 0;

   if (size > 0 && size < PIPE_BUF)
      if (pipe(fd.fds) != -1) {
	 fd.pipe = 1;
	 return fd;
      }

   total_len = tempdir_len + TEMP_FILE_TEMPLATE_LEN;
   if (total_len > MAX_PATH_LENGTH) {
      log_error_time();
      fprintf(stderr, "Temporary file length (%d) is too long\n",
	      total_len);
      return EMPTY_FDS;
   }

   memcpy(boa_tempfile, tempdir, tempdir_len);
   memcpy(&boa_tempfile[tempdir_len], TEMP_FILE_TEMPLATE,
	  TEMP_FILE_TEMPLATE_LEN);
   boa_tempfile[total_len] = 0;	/* null terminated */

   fd.fds[0] = fd.fds[1] = -1;
   /* open temp file 
    */
   fd.fds[0] = mkstemp(boa_tempfile);
   if (fd.fds[0] == -1) {
      log_error_time();
      perror("mkstemp");
      return EMPTY_FDS;
   }

   if (want_unlink) {
      if (unlink(boa_tempfile) == -1) {
	 close(fd.fds[0]);
	 fd.fds[0] = -1;
	 log_error_time();
	 fprintf(stderr, "unlink temp file\n");
      }
   }

   fd.fds[1] = fd.fds[0];
   return (fd);
}

int set_block_fd(int fd)
{
   int flags;

   flags = fcntl(fd, F_GETFL);
   if (flags == -1)
      return -1;

   flags &= ~O_NONBLOCK;
   flags = fcntl(fd, F_SETFL, flags);
   return flags;
}

int set_nonblock_fd(int fd)
{
   int flags;

   flags = fcntl(fd, F_GETFL);
   if (flags == -1)
      return -1;

   flags |= O_NONBLOCK;
   flags = fcntl(fd, F_SETFL, flags);
   return flags;
}

int set_cloexec_fd(int fd)
{
   int flags;

   flags = fcntl(fd, F_GETFL);
   if (flags == -1)
      return -1;

   flags |= FD_CLOEXEC;
   flags = fcntl(fd, F_SETFL, flags);
   return flags;
}

void create_url(char *buffer, int buffer_size, int secure,
		const char *hostname, int port, const char *request_uri)
{
   char *proto;
   char str_port[23];
   int do_port = 0;

   buffer[0] = 0;		/* in case we fail */
   if (hostname == NULL)
      hostname = "";

   if (request_uri == NULL)
      request_uri = "";

   if (secure) {
      proto = "https";
      if (port != 443)
	 do_port = 1;
   } else {
      proto = "http";
      if (port != 80)
	 do_port = 1;
   }

   if (do_port) {
      str_port[0] = ':';
      simple_itoa(port, &str_port[1]);
   }

   if ((strlen(proto) + strlen(str_port) + strlen(hostname) +
	strlen(request_uri) + 5) > buffer_size) {
      /* This is more than impossible. The buffer is long enough */
      log_error_time();
      fprintf(stderr, "Could not create URL. Buffer was not enough.\n");
      return;
   }

   sprintf(buffer, "%s://%s%s%s/", proto, hostname, str_port, request_uri);

   return;
}

/* Breaks a list of "xxx", "yyy", to a character array, of
 * MAX_COMMA_SEP_ELEMENTS size; Note that the given string is modified.
 */
void break_comma_list(char *etag,
		      char *broken_etag[MAX_COMMA_SEP_ELEMENTS],
		      int *elements)
{
   char *p = etag;

   *elements = 0;

   do {
      broken_etag[*elements] = p;

      (*elements)++;

      p = strchr(p, ',');
      if (p) {
	 *p = 0;
	 p++;			/* move to next entry and skip white
				 * space.
				 */
	 while (*p == ' ')
	    p++;
      }
   } while (p != NULL && *elements < MAX_COMMA_SEP_ELEMENTS);
}

/* Quoting from rfc1034:

<domain> ::= <subdomain> | " "

<subdomain> ::= <label> | <subdomain> "." <label>

<label> ::= <letter> [ [ <ldh-str> ] <let-dig> ]

<ldh-str> ::= <let-dig-hyp> | <let-dig-hyp> <ldh-str>

<let-dig-hyp> ::= <let-dig> | "-"

<let-dig> ::= <letter> | <digit>

<letter> ::= any one of the 52 alphabetic characters A through Z in
upper case and a through z in lower case

<digit> ::= any one of the ten digits 0 through 9

and

The labels must follow the rules for ARPANET host names.  They must
start with a letter, end with a letter or digit, and have as interior
characters only letters, digits, and hyphen.  There are also some
restrictions on the length.  Labels must be 63 characters or less.

*/

int check_host(char *r)
{
   /* a hostname can only consist of
    * chars and numbers, and sep. by only
    * one period.
    * It may not end with a period, and must
    * not start with a number.
    *
    * >0: correct
    * -1: error
    *  0: not returned
    *
    */
   char *c;
   short period_ok = 0;
   short len = 0;

   c = r;
   if (c == NULL) {
      return -1;
   }

   /* must start with a letter */
   if (!isalpha(*c))
      return -1;

   len = 1;
   while (*(++c) != '\0') {
      /* interior letters may be alphanumeric, '-', or '.' */
      /* '.' may not follow '.' */
      if (isalnum(*c) || *c == '-')
	 period_ok = 1;
      else if (*c == '.' && period_ok)
	 period_ok = 0;
      else
	 return -1;
      ++len;
   }
   /* c points to '\0' */
   --c;
   /* must end with a letter or digit */
   if (!isalnum(*c))
      return -1;
   return len;
}

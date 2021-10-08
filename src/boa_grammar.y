%{

/*
 *  Boa, an http server
 *  Copyright (C) 1995 Paul Phillips <psp@well.com>
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

/* $Id: boa_grammar.y,v 1.4 2002/10/27 10:06:28 nmav Exp $*/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
/* #include "boa.h" */
#include "parse.h"

int yyerror(char * msg);

/* yydebug = 1; */
#ifdef DEBUG
#define DBG(x) x
#else
#define DBG(x)
#endif

char *arg1hold;
char *arg2hold;
char *arg3hold;
char mime_type[256];            /* global to inherit */

%}

%union {
    char *	sval;
    int		ival;
    struct ccommand * cval;
};

/* boa.conf tokens */
%token <cval> STMT_NO_ARGS STMT_ONE_ARG STMT_TWO_ARGS STMT_THREE_ARGS STMT_FOUR_ARGS

/* mime.type tokens */
%token <sval> MIMETYPE
%token <sval> STRING
%token <ival> INTEGER
%token STRING_SEP ':'

%start ConfigFiles

%%

ConfigFiles:		BoaConfigStmts MimeTypeStmts
	;

BoaConfigStmts:		BoaConfigStmts BoaConfigStmt
	|		/* empty */
	;

BoaConfigStmt:		
			StmtNoArgs
	|		StmtOneArg
	|		StmtTwoArgs
	|		StmtThreeArgs
	|		StmtFourArgs
	;

StmtNoArgs:		STMT_NO_ARGS
		{ if ($1->action) {
			DBG(printf("StmtNoArgs: %s\n",$1->name);)
			$1->action(NULL, NULL, NULL,NULL,$1->object);
		 }
		}
	;

StmtOneArg:		STMT_ONE_ARG STRING
		{ if ($1->action) {
			DBG(printf("StmtOneArg: %s %s\n",$1->name,$2);)
			$1->action($2,NULL, NULL, NULL,$1->object);
		 }
		}
	;

StmtTwoArgs:		STMT_TWO_ARGS STRING
		{ arg1hold = strdup($2); }
			 STRING
		{ if ($1->action) {
			DBG(printf("StmtTwoArgs: '%s' '%s' '%s'\n",
			            $1->name,arg1hold,$4);)
			$1->action(arg1hold, $4,NULL, NULL, $1->object);
		  }
		  free(arg1hold);
		}
	;

StmtThreeArgs:		STMT_THREE_ARGS STRING
		{ arg1hold = strdup($2); }
			 STRING
		{ arg2hold = strdup($4); }
			 STRING
		{ if ($1->action) {
			DBG(printf("StmtThreeArgs: '%s' '%s' '%s' '%s'\n",
			            $1->name,arg1hold, arg2hold, $6);)
			$1->action(arg1hold, arg2hold, $6, NULL, $1->object);
		  }
		  free(arg1hold);
		  free(arg2hold);
		}
	;

StmtFourArgs:		STMT_FOUR_ARGS STRING
		{ arg1hold = strdup($2); }
			 STRING
		{ arg2hold = strdup($4); }
			 STRING
		{ arg3hold = strdup($6); }
			 STRING
		{ if ($1->action) {
			DBG(printf("StmtFourArgs: '%s' '%s' '%s' '%s' '%s'\n",
			            $1->name,arg1hold, arg2hold, arg3hold, $8);)
			$1->action(arg1hold, arg2hold, arg3hold, $8, $1->object);
		  }
		  free(arg1hold);
		  free(arg2hold);
		  free(arg3hold);
		}
	;

/******************* mime.types **********************/

MimeTypeStmts:		MimeTypeStmts MimeTypeStmt
	|		/* empty */
	;

MimeTypeStmt:		MIMETYPE 
		{ strcpy(mime_type, $1); }
			ExtensionList
	;

ExtensionList:		ExtensionList Extension
	|		/* empty */
	;

Extension:		STRING
		{ add_mime_type($1, mime_type); }
	;

%%


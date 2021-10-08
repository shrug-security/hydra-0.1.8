#ifndef BISON_BOA_GRAMMAR_H
# define BISON_BOA_GRAMMAR_H

#ifndef YYSTYPE
typedef union {
    char *	sval;
    int		ival;
    struct ccommand * cval;
} yystype;
# define YYSTYPE yystype
#endif
# define	STMT_NO_ARGS	257
# define	STMT_ONE_ARG	258
# define	STMT_TWO_ARGS	259
# define	STMT_THREE_ARGS	260
# define	STMT_FOUR_ARGS	261
# define	MIMETYPE	262
# define	STRING	263
# define	INTEGER	264
# define	STRING_SEP	265


extern YYSTYPE yylval;

#endif /* not BISON_BOA_GRAMMAR_H */

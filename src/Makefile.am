INCLUDES = -I../
EXTRA_DIST = boa.h compat.h defines.h escape.h globals.h parse.h socket.h \
   ssl.h boa_grammar.h webindex.pl queue.h loop_signals.h access.h

GCC_FLAGS = -Wstrict-prototypes -Wpointer-arith -Wcast-align -Wcast-qual\
  -Wtraditional\
  -Wshadow\
  -Wconversion\
  -Waggregate-return\
  -Wmissing-prototypes\
  -Wnested-externs\
  -Wall \
  -Wundef -Wwrite-strings -Wredundant-decls -Winline


bin_PROGRAMS = hydra boa_indexer 
bin_SCRIPTS = webindex.pl
hydra_SOURCES = alias.c boa.c buffer.c cgi.c cgi_header.c config.c escape.c \
	get.c hash.c ip.c log.c mmap_cache.c pipe.c queue.c read.c \
	request.c response.c select.c signals.c util.c sublog.c ssl.c \
	socket.c virthost.c index.c boa_grammar.y boa_lexer.l timestamp.c \
	strutil.c cgi_ssl.c poll.c access.c action_cgi.c
hydra_LDADD = $(LIBGNUTLS_LIBS)

boa_indexer_SOURCES = index_dir.c escape.c scandir.c strutil.c

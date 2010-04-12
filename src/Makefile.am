AM_CFLAGS = -D_OFFSET_BITS=64 -D_LARGEFILE_SOURCE
bin_PROGRAMS = nfex
nfex_SOURCES = 		main.c \
			packet.c \
			init.c \
			sessionlist.c \
			sessionlist.h \
			util.c \
			util.h \
			confy.y \
			confl.l \
			conf.c \
			conf.h \
			confy.h \
			search.h \
			search.c \
			extract.h \
			extract.c \
			asynch.c

# tcpxtract_LDADD = @LEXLIB@

sysconf_DATA = ../conf/nfex.conf

# man_MANS = ../doc/tcpxtract.1 

# EXTRA_DIST = ../conf/nfex.conf ../doc/nfex.1

AM_YFLAGS = -d

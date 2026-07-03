# libdmsg - HAMMER2 network cluster messaging library (OpenBSD userland port)
#
# Ported from DragonFly BSD lib/libdmsg.  OpenBSD adaptations live in
# dmsg_compat.h (atomic_*/bswap*) and dmsg_local.h (<util.h>, compat include);
# the on-wire protocol header <sys/dmsg.h> is provided by ../../sys/sys/dmsg.h.

LIB=	dmsg

SRCS=	debug.c subs.c crypto.c msg.c msg_lnk.c service.c
SRCS+=	icrc32.c

.PATH:	${.CURDIR}/../../sys/libkern

# <sys/dmsg.h> (on-wire protocol) from the port's userland sys/ mirror.
CFLAGS+=	-I${.CURDIR}/../../sys
CFLAGS+=	-pthread
# LibreSSL marks the low-level SHA/RSA/EVP calls deprecated; hammer2 uses them.
CFLAGS+=	-Wno-deprecated-declarations

INCS=	dmsg.h
INCSDIR=	/usr/include

.include <bsd.lib.mk>

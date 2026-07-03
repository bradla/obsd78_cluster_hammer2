.include <bsd.own.mk>

PROG=	destroy_hammer2
SRCS=	destroy.c ondisk.c subs.c xxhash.c icrc32.c
NOMAN=	yes

.PATH:	../hammer2 ../../sys/libkern ../../sys/fs/hammer2/xxhash

WARNS=	5

CFLAGS+=	-I../../sys
CFLAGS+=	-I../hammer2

DPADD+=		${LIBCRYPTO}
LDADD+=		-lcrypto

.include <bsd.prog.mk>

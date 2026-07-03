.include <bsd.own.mk>

PROG=	hammer2
SRCS=	cmd_bulkfree.c cmd_cleanup.c hammer2_compression.c cmd_debug.c \
	cmd_destroy.c cmd_emergency.c cmd_growfs.c cmd_pfs.c cmd_recover.c \
	cmd_setcheck.c cmd_setcomp.c cmd_snapshot.c cmd_stat.c cmd_volume.c \
	hammer2_lz4.c main.c ondisk.c print_inode.c subs.c xxhash.c icrc32.c
# cluster / network cluster-controller commands (need libdmsg)
SRCS+=	cmd_service.c cmd_remote.c cmd_rsa.c cmd_info.c cmd_leaf.c
MAN=	hammer2.8

.PATH:	../../sys/libkern ../../sys/fs/hammer2 ../../sys/fs/hammer2/xxhash

WARNS=	5

CFLAGS+=	-I../../sys
CFLAGS+=	-I../../lib/libdmsg	# <dmsg.h>
CFLAGS+=	-DZLIB_CONST
CFLAGS+=	-pthread

# error: 'SHA256_xxx' is deprecated [-Werror,-Wdeprecated-declarations]
CFLAGS+=	-Wno-deprecated-declarations

# libdmsg (built in ../../lib/libdmsg) + its transitive deps
LDADD+=		../../lib/libdmsg/libdmsg.a
DPADD+=		../../lib/libdmsg/libdmsg.a

DPADD+=		${LIBCRYPTO}
LDADD+=		-lcrypto

DPADD+=		${LIBZ}
LDADD+=		-lz

LDADD+=		-lpthread

.include <bsd.prog.mk>

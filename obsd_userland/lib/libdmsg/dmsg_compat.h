/*
 * OpenBSD userland compat shim for libdmsg.
 *
 * libdmsg is ported from DragonFly BSD, whose userland provides
 * <machine/atomic.h> (atomic_*_int) and <sys/endian.h> bswapNN() to userland.
 * OpenBSD does not, so provide equivalents here via compiler builtins.  These
 * are used from the multi-threaded (pthread) iocom/state machinery, so real
 * atomics are required.
 */
#ifndef _DMSG_COMPAT_H_
#define _DMSG_COMPAT_H_

#include <sys/types.h>
#include <sys/cdefs.h>

/*
 * DragonFly/FreeBSD spell the printf-format attribute __printflike(); OpenBSD
 * <sys/cdefs.h> does not provide it (it uses __attribute__((__format__)) or
 * __printf0like directly).  Provide it if absent.
 */
#ifndef __printflike
#define __printflike(fmtarg, firstvararg)	\
	__attribute__((__format__(__printf__, fmtarg, firstvararg)))
#endif

/*
 * FreeBSD/DragonFly libutil provides realhostname_sa() (forward/reverse-DNS
 * validated reverse lookup); OpenBSD does not.  libdmsg uses it only for a
 * debug printout of the peer's hostname, so a plain getnameinfo() reverse
 * lookup is a faithful substitute.
 */
#include <sys/socket.h>
#include <netdb.h>

#define HOSTNAME_FOUND		0
#define HOSTNAME_INCORRECTNAME	1
#define HOSTNAME_INVALIDADDR	2
#define HOSTNAME_INVALIDNAME	3

static __inline int
realhostname_sa(char *host, size_t hsize, struct sockaddr *addr, int addrlen)
{
	if (getnameinfo(addr, addrlen, host, hsize, NULL, 0, NI_NAMEREQD) == 0)
		return (HOSTNAME_FOUND);
	return (HOSTNAME_INVALIDADDR);
}

/*
 * Atomic bit / counter operations on 32-bit ints.
 * DragonFly semantics:
 *   atomic_set_int(p, bits)      *p |= bits
 *   atomic_clear_int(p, bits)    *p &= ~bits
 *   atomic_add_int(p, v)         *p += v
 *   atomic_fetchadd_int(p, v)    tmp = *p; *p += v; return tmp
 */
static __inline void
atomic_set_int(volatile unsigned int *p, unsigned int bits)
{
	__sync_fetch_and_or(p, bits);
}

static __inline void
atomic_clear_int(volatile unsigned int *p, unsigned int bits)
{
	__sync_fetch_and_and(p, ~bits);
}

static __inline void
atomic_add_int(volatile unsigned int *p, int v)
{
	__sync_fetch_and_add(p, v);
}

static __inline unsigned int
atomic_fetchadd_int(volatile unsigned int *p, int v)
{
	return (__sync_fetch_and_add(p, v));
}

/*
 * Byte-swap helpers.  OpenBSD spells these swapNN(); DragonFly uses bswapNN().
 */
#ifndef bswap16
#define bswap16(x)	__builtin_bswap16(x)
#endif
#ifndef bswap32
#define bswap32(x)	__builtin_bswap32(x)
#endif
#ifndef bswap64
#define bswap64(x)	__builtin_bswap64(x)
#endif

#endif /* _DMSG_COMPAT_H_ */

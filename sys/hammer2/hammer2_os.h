/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2022-2023 Tomohiro Kusumi <tkusumi@netbsd.org>
 * Copyright (c) 2011-2022 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@dragonflybsd.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _FS_HAMMER2_OS_H_
#define _FS_HAMMER2_OS_H_

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/malloc.h>
#include <sys/pool.h>
#include <sys/vnode.h>
#include <sys/atomic.h>

#include "hammer2_compat.h"

#ifdef HAMMER2_INVARIANTS
#define HFMT	"%s(%s|%d): "
#define HARGS	__func__, \
    curproc ? curproc->p_p->ps_comm : "-", \
    curproc ? curproc->p_tid : -1
#else
#define HFMT	"%s: "
#define HARGS	__func__
#endif

#define hprintf(X, ...)	printf(HFMT X, HARGS, ## __VA_ARGS__)
#define hpanic(X, ...)	panic(HFMT X, HARGS, ## __VA_ARGS__)

#ifdef HAMMER2_INVARIANTS
#define debug_hprintf	hprintf
#else
#define debug_hprintf(X, ...)	do {} while (0)
#endif

/* hammer2_lk is lockmgr(9) in DragonFly. */
/* mutex(9) is spinlock in OpenBSD. */
typedef struct rwlock hammer2_lk_t;

static __inline void
hammer2_lk_init(hammer2_lk_t *p, const char *s)
{
	rw_init(p, s);
}

static __inline void
hammer2_lk_ex(hammer2_lk_t *p)
{
	rw_enter_write(p);
}

static __inline void
hammer2_lk_unlock(hammer2_lk_t *p)
{
	rw_exit_write(p);
}

static __inline void
hammer2_lk_destroy(hammer2_lk_t *p __unused)
{
}

static __inline void
hammer2_lk_assert_ex(hammer2_lk_t *p)
{
	KASSERT(rw_status(p) == RW_WRITE);
}

static __inline void
hammer2_lk_assert_unlocked(hammer2_lk_t *p)
{
	KASSERT(rw_status(p) == 0);
}

typedef int hammer2_lkc_t;

static __inline void
hammer2_lkc_init(hammer2_lkc_t *c __unused, const char *s __unused)
{
}

static __inline void
hammer2_lkc_destroy(hammer2_lkc_t *c __unused)
{
}

static __inline void
hammer2_lkc_sleep(hammer2_lkc_t *c, hammer2_lk_t *p, const char *s)
{
	rwsleep(c, p, PCATCH, s, 0);
}

static __inline void
hammer2_lkc_wakeup(hammer2_lkc_t *c)
{
	wakeup(c);
}

/*
 * Mutex and spinlock shims.
 * Normal synchronous non-abortable locks can be substituted for spinlocks.
 * OpenBSD HAMMER2 currently uses rrwlock(9) for mtx and rwlock(9) for spinlock.
 */
struct rrwlock_wrapper {
	struct rrwlock lock;
	int refs;
	const char *lfile;	/* TEMP DIAG: where last locked */
	int lline;
};
typedef struct rrwlock_wrapper hammer2_mtx_t;

static __inline void
hammer2_mtx_init(hammer2_mtx_t *p, const char *s)
{
	bzero(p, sizeof(*p));
	rrw_init(&p->lock, s);
}

static __inline void
hammer2_mtx_init_recurse(hammer2_mtx_t *p, const char *s)
{
	bzero(p, sizeof(*p));
	rrw_init(&p->lock, s);
}

/*
 * TEMP DIAGNOSTIC: OpenBSD's rrwlock cannot upgrade read->write.  The macros
 * below capture the caller's __FILE__/__LINE__; on a would-block that never
 * clears we panic() reporting BOTH the requester (this call) and the current
 * holder (recorded on the last successful lock), so a single console photo
 * names the offending SHARED-then-EXCLUSIVE pair -- no debugger needed.
 */
static __inline void
_hammer2_mtx_ex(hammer2_mtx_t *p, const char *file, int line)
{
	/*
	 * Stock DragonFly semantics: block until the exclusive lock is
	 * available, letting current shared/exclusive holders run and release.
	 * A plain sleeping rrw_enter(RW_WRITE) can't be used because if THIS
	 * thread already holds the lock shared, rrwlock cannot upgrade and would
	 * sleep forever.  So we retry with RW_NOSLEEP but *yield the CPU* between
	 * attempts (tsleep, not delay) so the holder can make progress -- the
	 * earlier delay()-spin starved the very holder it waited on.  If it is
	 * still stuck after ~4s we log the requester/holder and block (do not
	 * panic) so the box stays up for ps(1) inspection of the wedged holder.
	 */
	if (rrw_enter(&p->lock, RW_WRITE | RW_NOSLEEP) != 0) {
		int _i;

		for (_i = 0; _i < 400; ++_i) {		/* ~4s of yielding */
			tsleep(p, 0, "h2exwait", 1);	/* yield ~1 tick */
			if (rrw_enter(&p->lock, RW_WRITE | RW_NOSLEEP) == 0)
				goto acquired;
		}
		/*
		 * TEMP DIAG: still stuck after 4s.  Print who is waiting and who
		 * holds it (once), then BLOCK (sleeping) rather than panic, so the
		 * box survives to a login and the stuck shared holder can be
		 * inspected with ps(1).
		 */
		printf("hammer2_mtx_ex STALL: req %s:%d holder %s:%d "
		    "lock=%p refs=%d pid=%d -- blocking\n", file, line,
		    p->lfile ? p->lfile : "?", p->lline, p, p->refs,
		    curproc ? curproc->p_p->ps_pid : -1);
		rrw_enter(&p->lock, RW_WRITE);		/* block, do not halt */
	}
acquired:
	p->lfile = file;
	p->lline = line;
	atomic_add_int(&p->refs, 1);
}
#define hammer2_mtx_ex(p)	_hammer2_mtx_ex((p), __FILE__, __LINE__)

static __inline void
_hammer2_mtx_sh(hammer2_mtx_t *p, const char *file, int line)
{
	/*
	 * If this thread already owns the lock exclusively, a shared request
	 * is weaker and is already satisfied.  OpenBSD's rrwlock deadlocks on
	 * RW_READ-over-own-RW_WRITE, so recurse as RW_WRITE instead (DragonFly's
	 * mtx allows shared-over-exclusive-by-self the same way).
	 */
	int how = (rrw_status(&p->lock) == RW_WRITE) ? RW_WRITE : RW_READ;

	if (rrw_enter(&p->lock, how | RW_NOSLEEP) != 0) {
		int _i;

		for (_i = 0; _i < 400; ++_i) {		/* ~4s of yielding */
			tsleep(p, 0, "h2shwait", 1);
			if (rrw_enter(&p->lock, how | RW_NOSLEEP) == 0)
				goto acquired;
		}
		/* TEMP DIAG: same as mtx_ex -- log stuck holder, then block. */
		printf("hammer2_mtx_sh STALL: req %s:%d holder %s:%d "
		    "lock=%p refs=%d pid=%d how=%d -- blocking\n", file, line,
		    p->lfile ? p->lfile : "?", p->lline, p, p->refs,
		    curproc ? curproc->p_p->ps_pid : -1, how);
		rrw_enter(&p->lock, how);		/* block, do not halt */
	}
acquired:
	p->lfile = file;
	p->lline = line;
	atomic_add_int(&p->refs, 1);
}
#define hammer2_mtx_sh(p)	_hammer2_mtx_sh((p), __FILE__, __LINE__)

static __inline void
hammer2_mtx_unlock(hammer2_mtx_t *p)
{
	atomic_add_int(&p->refs, -1);
	rrw_exit(&p->lock);
}

static __inline int
hammer2_mtx_refs(hammer2_mtx_t *p)
{
	return (p->refs);
}

static __inline void
hammer2_mtx_destroy(hammer2_mtx_t *p __unused)
{
}

/* Non-zero if exclusively locked by the calling thread. */
static __inline int
hammer2_mtx_owned(hammer2_mtx_t *p)
{
	return (rrw_status(&p->lock) == RW_WRITE);
}

/* RW_READ doesn't necessarily mean read locked by calling thread. */
static __inline void
hammer2_mtx_assert_ex(hammer2_mtx_t *p)
{
	KASSERT(rrw_status(&p->lock) == RW_WRITE);
}

static __inline void
hammer2_mtx_assert_sh(hammer2_mtx_t *p)
{
	/*
	 * A shared assertion passes if held shared, or if this thread holds it
	 * exclusive (exclusive satisfies a shared expectation -- see
	 * _hammer2_mtx_sh's recurse-as-write path).
	 */
	KASSERT(rrw_status(&p->lock) == RW_READ ||
	    rrw_status(&p->lock) == RW_WRITE);
}

static __inline void
hammer2_mtx_assert_locked(hammer2_mtx_t *p)
{
	KASSERT(rrw_status(&p->lock) == RW_READ || rrw_status(&p->lock) == RW_WRITE);
}

static __inline void
hammer2_mtx_assert_unlocked(hammer2_mtx_t *p)
{
	KASSERT(rrw_status(&p->lock) == 0);
}

static __inline int
_hammer2_mtx_ex_try(hammer2_mtx_t *p, const char *file, int line)
{
	if (!rrw_enter(&p->lock, RW_WRITE|RW_NOSLEEP)) {
		p->lfile = file;
		p->lline = line;
		atomic_add_int(&p->refs, 1);
		return (0);
	} else {
		return (1);
	}
}
#define hammer2_mtx_ex_try(p)	_hammer2_mtx_ex_try((p), __FILE__, __LINE__)

static __inline int
_hammer2_mtx_sh_try(hammer2_mtx_t *p, const char *file, int line)
{
	int how = (rrw_status(&p->lock) == RW_WRITE) ? RW_WRITE : RW_READ;

	if (!rrw_enter(&p->lock, how|RW_NOSLEEP)) {
		p->lfile = file;
		p->lline = line;
		atomic_add_int(&p->refs, 1);
		return (0);
	} else {
		return (1);
	}
}
#define hammer2_mtx_sh_try(p)	_hammer2_mtx_sh_try((p), __FILE__, __LINE__)

static __inline int
hammer2_mtx_upgrade_try(hammer2_mtx_t *p)
{
	KASSERT(rrw_status(&p->lock) != 0);
	if (hammer2_mtx_owned(p))
		return (0);

	hammer2_mtx_unlock(p); /* XXX */

	return (hammer2_mtx_ex_try(p));
}

static __inline int
hammer2_mtx_temp_release(hammer2_mtx_t *p)
{
	int x;

	x = hammer2_mtx_owned(p);
	hammer2_mtx_unlock(p);

	return (x);
}

static __inline void
hammer2_mtx_temp_restore(hammer2_mtx_t *p, int x)
{
	if (x)
		hammer2_mtx_ex(p);
	else
		hammer2_mtx_sh(p);
}

typedef struct rwlock hammer2_spin_t;

static __inline void
hammer2_spin_init(hammer2_spin_t *p, const char *s)
{
	rw_init(p, s);
}

static __inline void
hammer2_spin_ex(hammer2_spin_t *p)
{
	rw_enter(p, RW_WRITE);
}

static __inline void
hammer2_spin_sh(hammer2_spin_t *p)
{
	rw_enter(p, RW_READ);
}

static __inline void
hammer2_spin_unex(hammer2_spin_t *p)
{
	rw_exit(p);
}

static __inline void
hammer2_spin_unsh(hammer2_spin_t *p)
{
	rw_exit(p);
}

static __inline void
hammer2_spin_destroy(hammer2_spin_t *p __unused)
{
}

static __inline void
hammer2_spin_assert_ex(hammer2_spin_t *p)
{
	rw_assert_wrlock(p);
}

static __inline void
hammer2_spin_assert_sh(hammer2_spin_t *p)
{
	rw_assert_rdlock(p);
}

static __inline void
hammer2_spin_assert_locked(hammer2_spin_t *p)
{
	rw_assert_anylock(p);
}

static __inline void
hammer2_spin_assert_unlocked(hammer2_spin_t *p)
{
	rw_assert_unlocked(p);
}

extern struct pool hammer2_pool_inode;
extern struct pool hammer2_pool_xops;

extern int malloc_leak_m_hammer2;
extern int malloc_leak_m_hammer2_rbuf;
extern int malloc_leak_m_hammer2_wbuf;
extern int malloc_leak_m_hammer2_lz4;
extern int malloc_leak_m_temp;

//#define HAMMER2_MALLOC
#ifdef HAMMER2_MALLOC
static __inline void
adjust_malloc_leak(int delta, int type)
{
	int *lp;

	switch (type) {
	case M_HAMMER2:
		lp = &malloc_leak_m_hammer2;
		break;
	case M_HAMMER2_RBUF:
		lp = &malloc_leak_m_hammer2_rbuf;
		break;
	case M_HAMMER2_WBUF:
		lp = &malloc_leak_m_hammer2_wbuf;
		break;
	case M_HAMMER2_LZ4:
		lp = &malloc_leak_m_hammer2_lz4;
		break;
	case M_TEMP:
		lp = &malloc_leak_m_temp;
		break;
	default:
		hpanic("bad malloc type %d", type);
		break;
	}
	atomic_add_int(lp, delta);
}

static __inline void *
hmalloc(size_t size, int type, int flags)
{
	void *addr;

	flags &= ~M_WAITOK;
	flags |= M_NOWAIT;

	addr = malloc(size, type, flags);
	KASSERTMSG(addr, "size %ld type %d flags %x malloc_leak %d,%d,%d,%d,%d",
	    (long)size, type, flags,
	    malloc_leak_m_hammer2,
	    malloc_leak_m_hammer2_rbuf,
	    malloc_leak_m_hammer2_wbuf,
	    malloc_leak_m_hammer2_lz4,
	    malloc_leak_m_temp);
	if (addr) {
		KKASSERT(size > 0);
		adjust_malloc_leak(size, type);
	}

	return (addr);
}

static __inline void
hfree(void *addr, int type, size_t freedsize)
{
	if (addr) {
		KKASSERT(freedsize > 0);
		adjust_malloc_leak(-(int)freedsize, type);
	}
	free(addr, type, freedsize);
}

static __inline char *
hstrdup(const char *str)
{
	size_t len;
	char *copy;

	len = strlen(str) + 1;
	copy = hmalloc(len, M_TEMP, M_NOWAIT);
	if (copy == NULL)
		return (NULL);
	bcopy(str, copy, len);

	return (copy);
}
#else
#define hmalloc(size, type, flags)	malloc(size, type, flags)
#define hfree(addr, type, freedsize)	free(addr, type, freedsize)

static __inline char *
hstrdup(const char *str)
{
	size_t len;
	char *copy;

	len = strlen(str) + 1;
	copy = hmalloc(len, M_TEMP, M_WAITOK);
	bcopy(str, copy, len);

	return (copy);
}
#endif

static __inline void
hstrfree(char *str)
{
	hfree(str, M_TEMP, strlen(str) + 1);
}

extern const struct vops hammer2_vops;
extern const struct vops hammer2_specvops;
#ifdef FIFO
extern const struct vops hammer2_fifovops;
#endif

#endif /* !_FS_HAMMER2_OS_H_ */

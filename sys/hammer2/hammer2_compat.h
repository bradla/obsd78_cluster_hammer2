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

#ifndef _FS_HAMMER2_COMPAT_H_
#define _FS_HAMMER2_COMPAT_H_

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cdefs.h>
#include <sys/stdint.h>
#include <sys/atomic.h>

#include <machine/cpufunc.h>

/* Taken from sys/sys/cdefs.h in FreeBSD. */
#define __DECONST(type, var)	((type)(__uintptr_t)(const void *)(var))

#if 0
#define HAMMER2_INVARIANTS
#endif

/* Emulate INVARIANTS in FreeBSD. */
#if 1
#define INVARIANTS	DIAGNOSTIC
#define __diagused	__unused
#else
#define INVARIANTS	DEBUG
#define __diagused	__unused
#endif

/* DragonFly KKASSERT is OpenBSD KASSERT equivalent. */
#define KKASSERT	KASSERT

#define rounddown2(x, y) ((x) & ~((y) - 1))	/* y power of two */

#define atomic_set_int		atomic_setbits_int
#define atomic_clear_int	atomic_clearbits_int

#define atomic_set_32		atomic_set_int
#define atomic_add_32		atomic_add_int

/*
 * 64-bit atomic OR.  hammer2_io.refs packs the DIO_* flag bits (DIO_GOOD,
 * DIO_DIRTY, ...) in the high bits of a 64-bit word, so a 32-bit set would
 * silently drop them.  x86_atomic_setbits_u64 comes from <machine/atomic.h>.
 */
#define atomic_set_64		x86_atomic_setbits_u64
#define atomic_clear_64		x86_atomic_clearbits_u64

#define atomic_cmpset_int(ptr, old, new)	\
	(atomic_cas_uint((ptr), (old), (new)) == (old))

#define atomic_cmpset_32	atomic_cmpset_int

/*
 * Must return a SUCCESS boolean (like atomic_cmpset_int above), not the old
 * value -- atomic_fetchadd_64() loops on !atomic_cmpset_64() and callers test
 * it as a boolean.  __sync_bool_compare_and_swap returns true iff it swapped.
 */
#define atomic_cmpset_64(ptr, old, new)		\
	(__sync_bool_compare_and_swap((ptr), (old), (new)))

//typedef int (*hammer2_chain_scan_b)(hammer2_chain_t *, void *);

static __inline unsigned int
atomic_fetchadd_int(volatile unsigned int *p, unsigned int v)
{
	unsigned int value;

	do {
		value = *p;
	} while (!atomic_cmpset_int(p, value, value + v));
	return (value);
}

static __inline uint32_t
atomic_fetchadd_32(volatile uint32_t *p, uint32_t v)
{
	uint32_t value;

	do {
		value = *p;
	} while (!atomic_cmpset_32(p, value, value + v));
	return (value);
}

static __inline uint64_t
atomic_fetchadd_64(volatile uint64_t *p, uint64_t v)
{
	uint64_t value;

	do {
		value = *p;
	} while (!atomic_cmpset_64(p, value, value + v));
	return (value);
}

#define cpu_pause()	CPU_BUSY_CYCLE()

/* Taken from sys/sys/cdefs.h in FreeBSD. */
#define __compiler_membar()	__asm __volatile(" " : : : "memory")
#define cpu_ccfence()	__compiler_membar()

#define getticks()	(ticks)

#define bqrelse(bp)	brelse(bp)

/*
 * Kernel-thread + interlocked-sleep primitives for the sync / xop-helper
 * threads (hammer2_admin.c, hammer2_synchro.c).
 *
 * OpenBSD has no interlocked tsleep().  The hammer2 thread signal/wait loops
 * re-check the flags after every wakeup, so a plain tsleep() with a bounded
 * timeout is correct -- a rarely-missed wakeup only costs one timeout period
 * of latency.  tsleep_interlock() therefore becomes a no-op and PINTERLOCKED
 * maps to a normal sleep priority.
 */
#include <sys/kthread.h>

/* PINTERLOCKED is defined as plain sleep priority 0 in hammer2.h.  OpenBSD's
 * tsleep() KASSERTs (priority & ~(PRIMASK|PCATCH)) == 0, so it cannot carry a
 * DragonFly-style interlock flag -- the old 0x400 value paniced the moment a
 * thr_wait/xop sleep ran.  tsleep_interlock() is therefore a no-op. */
#define tsleep_interlock(chan, flags)	do { } while (0)

#endif /* !_FS_HAMMER2_COMPAT_H_ */

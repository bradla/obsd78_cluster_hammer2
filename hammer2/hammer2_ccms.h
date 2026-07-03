/*
 * Copyright (c) 2006,2014-2018 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@backplane.com>
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

/*
 * CCMS - Cache Coherency Management System.
 *
 * This subsystem can be tied into a VFS in order to supply persistent
 * cache management state for cluster or for remote cache-coherent operations.
 *
 * Local and cluster/remote cache state is maintained in a cache-coherent
 * fashion as well as integrated into the VFS's inode locking subsystem
 * (as a means of avoiding deadlocks).
 *
 * The CCMS_CST structures represent granted cache and local locking states.
 * Grants can be recursively inherited, minimizing protocol overhead in
 * situations where there are no conflicts of interest.
 *
 * OpenBSD port note: this header must be included after "hammer2_os.h"
 * (via "hammer2.h"), which provides hammer2_spin_t.  DragonFly's
 * <sys/serialize.h> / <sys/spinlock.h> includes are dropped, thread_t is
 * mapped onto OpenBSD's struct proc *, and the sleep primitive maps to
 * rwsleep() since hammer2_spin_t is an rwlock (see hammer2_ccms.c).
 */

#ifndef _FS_HAMMER2_CCMS_H_
#define _FS_HAMMER2_CCMS_H_

#include <sys/types.h>
#include <sys/param.h>

typedef uint64_t	ccms_key_t;
typedef uint64_t	ccms_tid_t;
typedef uint8_t		ccms_state_t;
typedef uint8_t		ccms_type_t;

struct ccms_cst;

/*
 * CCMS_STATE_T - CCMS cache states.
 *
 * INVALID   -	Cache state is unknown and must be acquired.
 * SHARED    -	Cache state allows shared access.
 * EXCLUSIVE -  Cache state allows exclusive access.
 *
 * CCMS implements an extended MESI model.  The extensions are implemented
 * as CCMS_TYPE_T flags.
 */
#define CCMS_STATE_INVALID	0	/* unknown cache state */
#define CCMS_STATE_SHARED	2	/* clean, shared, read-only */
#define CCMS_STATE_EXCLUSIVE	3	/* clean, exclusive, read-only */

/*
 * CCMS_TYPE_T FLAGS
 *
 * INHERITED -  The state field was inherited and was not directly granted
 *		by the cluster controller.
 * MODIFIED  -  Type-field flag associated with an EXCLUSIVE cache state.
 * MASTER    -  EXCLUSIVE+MODIFIED state where slaves might be caching our
 *		unsynchronized state.
 * SLAVE     -  SHARED cache state whose data is being mastered elsewhere and
 *		has not yet been synchronized (no quorum run yet).
 * QSLAVE    -  The slaved data is also present in a quorum of master nodes.
 */
#define CCMS_TYPE_INHERITED	0x01
#define CCMS_TYPE_MODIFIED	0x02
#define CCMS_TYPE_MASTER	0x04
#define CCMS_TYPE_SLAVE		0x08
#define CCMS_TYPE_QSALVE	0x10
#define CCMS_TYPE_RECURSIVE	0x80

/*
 * CCMS_CST - Low level locking state, persistent cache state.
 *
 * count - Negative value indicates active exclusive lock, positive value
 *	   indicates active shared lock.
 * spin  - Structural spinlock (an rwlock in the OpenBSD port).
 * td    - Owning thread when exclusively locked (count < 0).  Mapped to
 *	   struct proc * on OpenBSD.
 */
struct ccms_cst {
	hammer2_spin_t	spin;		/* thread spinlock */
	ccms_state_t	state;		/* granted or inherited state */
	ccms_type_t	type;		/* CST type and flags */
	uint8_t		unused02;
	uint8_t		unused03;

	int32_t		upgrade;	/* upgrades pending */
	int32_t		count;		/* active shared/exclusive count */
	int32_t		blocked;	/* wakeup blocked on release */
	struct proc	*td;		/* if excl lock (count < 0) */
};

typedef struct ccms_cst		ccms_cst_t;

/*
 * Kernel API
 */
#ifdef _KERNEL

void ccms_cst_init(ccms_cst_t *cst);
void ccms_cst_uninit(ccms_cst_t *cst);

void ccms_thread_lock(ccms_cst_t *cst, ccms_state_t state);
int ccms_thread_lock_nonblock(ccms_cst_t *cst, ccms_state_t state);
ccms_state_t ccms_thread_lock_temp_release(ccms_cst_t *cst);
void ccms_thread_lock_temp_restore(ccms_cst_t *cst, ccms_state_t ostate);
ccms_state_t ccms_thread_lock_upgrade(ccms_cst_t *cst);
void ccms_thread_lock_downgrade(ccms_cst_t *cst, ccms_state_t ostate);
void ccms_thread_unlock(ccms_cst_t *cst);
void ccms_thread_unlock_upgraded(ccms_cst_t *cst, ccms_state_t ostate);
int ccms_thread_lock_owned(ccms_cst_t *cst);
void ccms_thread_lock_setown(ccms_cst_t *cst);

#endif /* _KERNEL */

#endif /* !_FS_HAMMER2_CCMS_H_ */

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
/*
 * This module implements the hammer2 helper thread API, including
 * the frontend/backend XOP API.
 */
 
#include "hammer2.h"

#define H2XOPDESCRIPTOR(label)					\
	hammer2_xop_desc_t hammer2_##label##_desc = {		\
		.storage_func = hammer2_xop_##label,		\
		.id = #label					\
	}

//void hammer2_chain_ref(hammer2_chain_t *);

H2XOPDESCRIPTOR(ipcluster);
H2XOPDESCRIPTOR(readdir);
H2XOPDESCRIPTOR(nresolve);
H2XOPDESCRIPTOR(unlink);
H2XOPDESCRIPTOR(nrename);
H2XOPDESCRIPTOR(scanlhc);
H2XOPDESCRIPTOR(scanall);
H2XOPDESCRIPTOR(lookup);
H2XOPDESCRIPTOR(delete);
H2XOPDESCRIPTOR(inode_mkdirent);
H2XOPDESCRIPTOR(inode_create);
H2XOPDESCRIPTOR(inode_create_det);
H2XOPDESCRIPTOR(inode_create_ins);
H2XOPDESCRIPTOR(inode_destroy);
H2XOPDESCRIPTOR(inode_chain_sync);
H2XOPDESCRIPTOR(inode_unlinkall);
H2XOPDESCRIPTOR(inode_connect);
H2XOPDESCRIPTOR(inode_flush);
H2XOPDESCRIPTOR(strategy_read);
H2XOPDESCRIPTOR(strategy_write);
H2XOPDESCRIPTOR(bmap);

//struct objcache *cache_xops;

/************************************************************************
 *			    THREAD MANAGEMENT				*
 ************************************************************************
 *
 * Kernel-thread management for the per-node synchronization threads (and,
 * in the future, XOP helper threads).  Ported from DragonFly.  OpenBSD
 * adaptations: lwkt_create() -> kthread_create() (no cpu affinity; name is
 * pre-formatted); tsleep_interlock()/PINTERLOCKED are handled by the compat
 * shim (no-op / normal priority); the flag-wait loops re-check after each
 * wakeup so a bounded 1-second sleep is safe.
 */

/*
 * Set flags and wakeup any waiters.
 *
 * WARNING! During teardown (thr) can disappear the instant our cmpset
 *	    succeeds.
 */
void
hammer2_thr_signal(hammer2_thread_t *thr, uint32_t flags)
{
	uint32_t oflags;
	uint32_t nflags;

	for (;;) {
		oflags = thr->flags;
		cpu_ccfence();
		nflags = (oflags | flags) & ~HAMMER2_THREAD_WAITING;

		if (oflags & HAMMER2_THREAD_WAITING) {
			if (atomic_cmpset_int(&thr->flags, oflags, nflags)) {
				wakeup(&thr->flags);
				break;
			}
		} else {
			if (atomic_cmpset_int(&thr->flags, oflags, nflags))
				break;
		}
	}
}

/*
 * Set and clear flags and wakeup any waiters.
 */
void
hammer2_thr_signal2(hammer2_thread_t *thr, uint32_t posflags, uint32_t negflags)
{
	uint32_t oflags;
	uint32_t nflags;

	for (;;) {
		oflags = thr->flags;
		cpu_ccfence();
		nflags = (oflags | posflags) &
			~(negflags | HAMMER2_THREAD_WAITING);
		if (oflags & HAMMER2_THREAD_WAITING) {
			if (atomic_cmpset_int(&thr->flags, oflags, nflags)) {
				wakeup(&thr->flags);
				break;
			}
		} else {
			if (atomic_cmpset_int(&thr->flags, oflags, nflags))
				break;
		}
	}
}

/*
 * Wait until all the bits in flags are set.
 */
void
hammer2_thr_wait(hammer2_thread_t *thr, uint32_t flags)
{
	uint32_t oflags;
	uint32_t nflags;

	for (;;) {
		oflags = thr->flags;
		cpu_ccfence();
		if ((oflags & flags) == flags)
			break;
		nflags = oflags | HAMMER2_THREAD_WAITING;
		tsleep_interlock(&thr->flags, 0);
		if (atomic_cmpset_int(&thr->flags, oflags, nflags)) {
			tsleep(&thr->flags, PINTERLOCKED, "h2twait", hz);
		}
	}
}

/*
 * Wait until any of the bits in flags are set, with timeout.
 */
int
hammer2_thr_wait_any(hammer2_thread_t *thr, uint32_t flags, int timo)
{
	uint32_t oflags;
	uint32_t nflags;
	int error;

	error = 0;
	for (;;) {
		oflags = thr->flags;
		cpu_ccfence();
		if (oflags & flags)
			break;
		nflags = oflags | HAMMER2_THREAD_WAITING;
		tsleep_interlock(&thr->flags, 0);
		if (atomic_cmpset_int(&thr->flags, oflags, nflags)) {
			error = tsleep(&thr->flags, PINTERLOCKED,
				       "h2twait", timo);
		}
		if (error == EWOULDBLOCK) {
			error = HAMMER2_ERROR_ETIMEDOUT;
			break;
		}
	}
	return (error);
}

/*
 * Wait until the bits in flags are clear.
 */
void
hammer2_thr_wait_neg(hammer2_thread_t *thr, uint32_t flags)
{
	uint32_t oflags;
	uint32_t nflags;

	for (;;) {
		oflags = thr->flags;
		cpu_ccfence();
		if ((oflags & flags) == 0)
			break;
		nflags = oflags | HAMMER2_THREAD_WAITING;
		tsleep_interlock(&thr->flags, 0);
		if (atomic_cmpset_int(&thr->flags, oflags, nflags)) {
			tsleep(&thr->flags, PINTERLOCKED, "h2twait", hz);
		}
	}
}

/*
 * Initialize the supplied thread structure, starting the specified thread.
 *
 * NOTE: thr structure can be retained across mounts and unmounts for this
 *	 pmp, so make sure the flags are in a sane state.
 */
void
hammer2_thr_create(hammer2_thread_t *thr, hammer2_pfs_t *pmp,
		   hammer2_dev_t *hmp,
		   const char *id, int clindex, int repidx,
		   void (*func)(void *arg))
{
	char name[MAXCOMLEN + 1];

	thr->pmp = pmp;		/* xop helpers */
	thr->hmp = hmp;		/* bulkfree */
	thr->clindex = clindex;
	thr->repidx = repidx;
	TAILQ_INIT(&thr->xopq);
	atomic_clear_int(&thr->flags, HAMMER2_THREAD_STOP |
				      HAMMER2_THREAD_STOPPED |
				      HAMMER2_THREAD_FREEZE |
				      HAMMER2_THREAD_FROZEN);
	if (thr->scratch == NULL)
		thr->scratch = hmalloc(MAXPHYS, M_HAMMER2, M_WAITOK | M_ZERO);

	/*
	 * OpenBSD kthread_create() has no cpu-affinity argument; drop repidx's
	 * "% ncpus" affinity and just format a descriptive name.
	 */
	if (repidx >= 0) {
		snprintf(name, sizeof(name), "%s-%s.%02d", id,
		    pmp->pfs_names[clindex], repidx);
	} else if (pmp) {
		snprintf(name, sizeof(name), "%s-%s", id,
		    pmp->pfs_names[clindex]);
	} else {
		snprintf(name, sizeof(name), "%s", id);
	}
	if (kthread_create(func, thr, &thr->td, name) != 0) {
		hprintf("failed to create kthread %s\n", name);
		thr->td = NULL;
	}
}

/*
 * Terminate a thread.  Silently returns if the thread was never initialized
 * or has already been deleted.  Sets STOP and waits for the thread to clear
 * its td and set STOPPED.
 */
void
hammer2_thr_delete(hammer2_thread_t *thr)
{
	if (thr->td == NULL)
		return;
	hammer2_thr_signal(thr, HAMMER2_THREAD_STOP);
	hammer2_thr_wait(thr, HAMMER2_THREAD_STOPPED);
	thr->pmp = NULL;
	if (thr->scratch) {
		hfree(thr->scratch, M_HAMMER2, MAXPHYS);
		thr->scratch = NULL;
	}
	KKASSERT(TAILQ_EMPTY(&thr->xopq));
}

/*
 * Asynchronous remaster request.  Ask the sync thread to start over soon.
 */
void
hammer2_thr_remaster(hammer2_thread_t *thr)
{
	if (thr->td == NULL)
		return;
	hammer2_thr_signal(thr, HAMMER2_THREAD_REMASTER);
}

void
hammer2_thr_freeze_async(hammer2_thread_t *thr)
{
	hammer2_thr_signal(thr, HAMMER2_THREAD_FREEZE);
}

void
hammer2_thr_freeze(hammer2_thread_t *thr)
{
	if (thr->td == NULL)
		return;
	hammer2_thr_signal(thr, HAMMER2_THREAD_FREEZE);
	hammer2_thr_wait(thr, HAMMER2_THREAD_FROZEN);
}

void
hammer2_thr_unfreeze(hammer2_thread_t *thr)
{
	if (thr->td == NULL)
		return;
	hammer2_thr_signal(thr, HAMMER2_THREAD_UNFREEZE);
	hammer2_thr_wait_neg(thr, HAMMER2_THREAD_FROZEN);
}

/*
 * Return non-zero if the thread should break out of its work loop (stop or
 * freeze requested).
 */
int
hammer2_thr_break(hammer2_thread_t *thr)
{
	if (thr->flags & (HAMMER2_THREAD_STOP |
			  HAMMER2_THREAD_REMASTER |
			  HAMMER2_THREAD_FREEZE)) {
		return (1);
	}
	return (0);
}

/*
 * Allocate or reallocate XOP FIFO.  This doesn't exist in DragonFly
 * where XOP is handled by dedicated kernel threads and when FIFO stalls
 * threads wait for frontend to collect results.
 */
static void
hammer2_xop_fifo_alloc(hammer2_xop_fifo_t *fifo, size_t new_nmemb,
    size_t old_nmemb)
{
	int flags = M_WAITOK | M_ZERO;
	size_t new_size, old_size;
	hammer2_chain_t **array;
	int *errors;

	/* Assert new vs old nmemb requirements. */
	KASSERT(new_nmemb > old_nmemb);
	if (old_nmemb == 0) {
		KASSERT(!fifo->array && !fifo->errors);
	} else {
		KKASSERT(fifo->array);
		KKASSERT(fifo->errors);
	}

	/* Assert new_nmemb requirements. */
	KKASSERT((new_nmemb & (new_nmemb - 1)) == 0);
	KKASSERT(new_nmemb >= HAMMER2_XOPFIFO);

	/* malloc or realloc fifo array. */
	new_size = new_nmemb * sizeof(hammer2_chain_t *);
	old_size = old_nmemb * sizeof(hammer2_chain_t *);
	array = hmalloc(new_size, M_HAMMER2, flags);
	if (fifo->array) {
		bcopy(fifo->array, array, old_size);
		hfree(fifo->array, M_HAMMER2, old_size);
	}
	fifo->array = array;
	KKASSERT(fifo->array);

	/* malloc or realloc fifo errors. */
	new_size = new_nmemb * sizeof(int);
	old_size = old_nmemb * sizeof(int);
	errors = hmalloc(new_size, M_HAMMER2, flags);
	if (fifo->errors) {
		bcopy(fifo->errors, errors, old_size);
		hfree(fifo->errors, M_HAMMER2, old_size);
	}
	fifo->errors = errors;
	KKASSERT(fifo->errors);
}

/*
 * Allocate a XOP request.
 * Once allocated a XOP request can be started, collected, and retired,
 * and can be retired early if desired.
 */
void *
hammer2_xop_alloc(hammer2_inode_t *ip, int flags)
{
	hammer2_xop_t *xop;
	int i;

	xop = pool_get(&hammer2_pool_xops, PR_WAITOK | PR_ZERO);
	KKASSERT(xop->head.cluster.array[0].chain == NULL);

	xop->head.ip1 = ip;
	xop->head.flags = flags;

	if (flags & HAMMER2_XOP_MODIFYING)
		xop->head.mtid = hammer2_trans_sub(ip->pmp);
	else
		xop->head.mtid = 0;

	xop->head.cluster.nchains = ip->cluster.nchains;
	xop->head.cluster.pmp = ip->pmp;
	hammer2_assert_cluster(&ip->cluster);

	/* run_mask - Frontend associated with XOP. */
	xop->head.run_mask = HAMMER2_XOPMASK_VOP;

	/*
	 * Allocate a collect FIFO for EVERY cluster node, not just node 0.
	 * hammer2_xop_feed() writes into collect[clindex] for each node, and
	 * hammer2_xop_retire() frees collect[0..nchains-1] -- allocating only
	 * node 0 left collect[1+].errors/array NULL and faulted feed() at
	 * nchains > 1.
	 */
	xop->head.fifo_size = HAMMER2_XOPFIFO;
	for (i = 0; i < xop->head.cluster.nchains; ++i)
		hammer2_xop_fifo_alloc(&xop->head.collect[i],
		    xop->head.fifo_size, 0);

	hammer2_inode_ref(ip);

	return (xop);
}

void
hammer2_xop_setname(hammer2_xop_head_t *xop, const char *name, size_t name_len)
{
	xop->name1 = hmalloc(name_len + 1, M_HAMMER2, M_WAITOK | M_ZERO);
	xop->name1_len = name_len;
	bcopy(name, xop->name1, name_len);
}

void
hammer2_xop_setname2(hammer2_xop_head_t *xop, const char *name, size_t name_len)
{
	xop->name2 = hmalloc(name_len + 1, M_HAMMER2, M_WAITOK | M_ZERO);
	xop->name2_len = name_len;
	bcopy(name, xop->name2, name_len);
}

size_t
hammer2_xop_setname_inum(hammer2_xop_head_t *xop, hammer2_key_t inum)
{
	const size_t name_len = 18;

	xop->name1 = hmalloc(name_len + 1, M_HAMMER2, M_WAITOK | M_ZERO);
	xop->name1_len = name_len;
	/* OpenBSD printf(9) variants don't support "%j..." */
	snprintf(xop->name1, name_len + 1, "0x%016llx", (long long)inum);

	return (name_len);
}

void
hammer2_xop_setip2(hammer2_xop_head_t *xop, hammer2_inode_t *ip2)
{
	xop->ip2 = ip2;
	hammer2_inode_ref(ip2);
}

void
hammer2_xop_setip3(hammer2_xop_head_t *xop, hammer2_inode_t *ip3)
{
	xop->ip3 = ip3;
	hammer2_inode_ref(ip3);
}

void
hammer2_xop_setip4(hammer2_xop_head_t *xop, hammer2_inode_t *ip4)
{
	xop->ip4 = ip4;
	hammer2_inode_ref(ip4);
}

/*
 * (Backend) Returns non-zero if the frontend is still attached.
 */
static __inline int
hammer2_xop_active(const hammer2_xop_head_t *xop)
{
	if (xop->run_mask & HAMMER2_XOPMASK_VOP)
		return (1);
	else
		return (0);
}

/*
 * hashinit(9) based hash to track inode dependencies.
 */
static int
xop_testset_ipdep(hammer2_inode_t *ip, int idx)
{
	hammer2_ipdep_list_t *ipdep;
	hammer2_inode_t *iptmp;

	hammer2_lk_assert_ex(&ip->pmp->xop_lock[idx]);

	ipdep = &ip->pmp->ipdep_lists[idx];
	LIST_FOREACH(iptmp, ipdep, ientry)
		if (iptmp == ip)
			return (1); /* collision */

	LIST_INSERT_HEAD(ipdep, ip, ientry);
	return (0);
}

static void
xop_unset_ipdep(hammer2_inode_t *ip, int idx)
{
	hammer2_ipdep_list_t *ipdep;
	hammer2_inode_t *iptmp;

	hammer2_lk_assert_ex(&ip->pmp->xop_lock[idx]);

	ipdep = &ip->pmp->ipdep_lists[idx];
	LIST_FOREACH(iptmp, ipdep, ientry)
		if (iptmp == ip) {
			LIST_REMOVE(ip, ientry);
			return;
		}
}

/*
 * Frontend inode-dependency serialization (synchronous-model helper).  Unused
 * in the threaded model -- hammer2_xop_next()'s dependency hash serializes
 * same-inode XOPs per worker thread instead.  Kept for reference.
 */
static void __unused
hammer2_xop_testset_ipdep(hammer2_inode_t *ip)
{
	hammer2_pfs_t *pmp = ip->pmp;
	hammer2_lk_t *mtx;
	hammer2_lkc_t *cv;

	mtx = &pmp->xop_lock[ip->ipdep_idx];
	cv = &pmp->xop_cv[ip->ipdep_idx];

	hammer2_lk_ex(mtx);
again:
	if (xop_testset_ipdep(ip, ip->ipdep_idx)) {
		pmp->flags |= HAMMER2_PMPF_WAITING;
		hammer2_lkc_sleep(cv, mtx, "h2pmp_xop");
		goto again;
	}
	hammer2_lk_unlock(mtx);
}

static void
hammer2_xop_unset_ipdep(hammer2_inode_t *ip)
{
	hammer2_pfs_t *pmp = ip->pmp;
	hammer2_lk_t *mtx;
	hammer2_lkc_t *cv;

	mtx = &pmp->xop_lock[ip->ipdep_idx];
	cv = &pmp->xop_cv[ip->ipdep_idx];

	hammer2_lk_ex(mtx);
	xop_unset_ipdep(ip, ip->ipdep_idx);
	if (pmp->flags & HAMMER2_PMPF_WAITING) {
		pmp->flags &= ~HAMMER2_PMPF_WAITING;
		hammer2_lkc_wakeup(cv);
	}
	hammer2_lk_unlock(mtx);
}

#ifdef HAMMER2_INVARIANTS
//#define XOP_ADMIN_DEBUG
static __inline void
xop_storage_func(hammer2_xop_head_t *xop, hammer2_inode_t *ip, void *scratch,
    int i)
{
#ifdef XOP_ADMIN_DEBUG
	hprintf("xop_%s inum %016llx index %d\n",
	    xop->desc->id, (long long)ip->meta.inum, i);
#endif
	xop->desc->storage_func((hammer2_xop_t *)xop, scratch, i);
#ifdef XOP_ADMIN_DEBUG
	hprintf("xop_%s inum %016llx index %d done\n",
	    xop->desc->id, (long long)ip->meta.inum, i);
#endif
}
#else
#define xop_storage_func(xop, ip, scratch, i)	\
	xop->desc->storage_func((hammer2_xop_t *)xop, scratch, i)
#endif

/*
 * Start a XOP request, queueing it to all nodes in the cluster to
 * execute the cluster op.
 */
void
hammer2_xop_start_except(hammer2_xop_head_t *xop, hammer2_xop_desc_t *desc,
    int notidx)
{
	hammer2_inode_t *ip = xop->ip1;
	hammer2_pfs_t *pmp = ip->pmp;
	hammer2_thread_t *thr;
	int i, ng, nchains;

	KKASSERT(ip);
	hammer2_assert_cluster(&ip->cluster);

	/*
	 * Make sure the backend xop worker threads exist for this pmp (a node
	 * may have been added to a live cluster after mount).
	 */
	if (pmp->has_xop_threads == 0)
		hammer2_xop_helper_create(pmp);

	xop->desc = desc;

	if (desc == &hammer2_strategy_write_desc)
		xop->scratch = hmalloc(hammer2_get_logical(), M_HAMMER2,
		    M_WAITOK | M_ZERO);

	/*
	 * Select a worker group.  Hash by inode so all operations on the same
	 * inode serialize to the same group's threads (where hammer2_xop_next's
	 * dependency-hash then serializes them).  The port has no strategy/cpu
	 * split, so group selection is otherwise arbitrary.
	 */
	ng = (unsigned int)ip->ihash % hammer2_xop_nthreads;

	/*
	 * Queue the XOP to each cluster node's worker thread.  The instant it
	 * is queued a backend thread may pick it off (and, for async ops, even
	 * free it), so do not touch xop after dropping xop_spin except via the
	 * per-thread pointers captured here.
	 */
	hammer2_spin_ex(&pmp->xop_spin);
	nchains = ip->cluster.nchains;
	for (i = 0; i < nchains; ++i) {
		if (i != notidx && ip->cluster.array[i].chain) {
			/*
			 * Front-end DATA-modifying ops (write, create, unlink,
			 * ...) are applied to MASTER nodes only -- this mirrors
			 * DragonFly, where hammer2_cluster_check() sets CITEM_FEMOD
			 * only on masters, so slaves are read-only from the
			 * frontend and brought up to date asynchronously by the
			 * per-node sync thread (hammer2_primary_sync_thread).
			 *
			 * The FLUSH and CHAIN_SYNC XOPs are the exception: like
			 * DragonFly they must reach EVERY node so each node commits
			 * its own dirty chains -- including the chains the sync
			 * thread just created on the slave.  Skipping them on the
			 * slave leaves the slave's modify_tid unadvanced and the
			 * sync thread loops forever (never converges).
			 *
			 * Non-modifying ops (reads) always fan out to all nodes
			 * for quorum.
			 */
			if (nchains >= 2 &&
			    (xop->flags & HAMMER2_XOP_MODIFYING) &&
			    desc != &hammer2_inode_flush_desc &&
			    desc != &hammer2_inode_chain_sync_desc &&
			    pmp->pfs_types[i] != HAMMER2_PFSTYPE_MASTER &&
			    pmp->pfs_types[i] != HAMMER2_PFSTYPE_SUPROOT)
				continue;
			thr = &pmp->xop_groups[ng].thrs[i];
			atomic_set_64(&xop->run_mask, 1LLU << i);
			atomic_set_64(&xop->chk_mask, 1LLU << i);
			xop->collect[i].thr = thr;
			TAILQ_INSERT_TAIL(&thr->xopq, xop, collect[i].entry);
		}
	}
	hammer2_spin_unex(&pmp->xop_spin);

	/* Signal each worker thread that has work. */
	for (i = 0; i < nchains; ++i) {
		if (i != notidx) {
			thr = &pmp->xop_groups[ng].thrs[i];
			hammer2_thr_signal(thr, HAMMER2_THREAD_XOPQ);
		}
	}
}

/*
 * Start an XOP on every cluster node.
 */
void
hammer2_xop_start(hammer2_xop_head_t *xop, hammer2_xop_desc_t *desc)
{
	hammer2_xop_start_except(xop, desc, -1);
}

/*
 * Retire a XOP.  Used by both the VOP frontend and by the XOP backend.
 */
void
hammer2_xop_retire(hammer2_xop_head_t *xop, uint64_t mask)
{
	hammer2_chain_t *chain, *dropch[HAMMER2_MAXCLUSTER];
	hammer2_inode_t *ip;
	hammer2_xop_fifo_t *fifo;
	uint64_t nmask;
	int prior_nchains, i;

	/*
	 * Remove the frontend collector or a backend feeder, adding a FEED bit
	 * so a waiting frontend re-checks.  When the frontend (VOP) terminates
	 * we wake any backend blocked on a full fifo; when the last backend
	 * terminates we wake a waiting frontend.
	 */
	KASSERTMSG(xop->run_mask & mask,
	    "run_mask %llx vs mask %llx",
	    (unsigned long long)xop->run_mask, (unsigned long long)mask);
	nmask = atomic_fetchadd_64(&xop->run_mask,
	    -mask + HAMMER2_XOPMASK_FEED);

	/* More than one entity left. */
	if ((nmask & HAMMER2_XOPMASK_ALLDONE) != mask) {
		/*
		 * NOTE: xop can be ripped out from under us here; wakeup(xop)
		 *	 does not dereference it so it is safe.
		 */
		if (mask == HAMMER2_XOPMASK_VOP) {
			if (nmask & HAMMER2_XOPMASK_FIFOW)
				wakeup(xop);
		}
		nmask -= mask;
		if ((nmask & HAMMER2_XOPMASK_ALLDONE) == HAMMER2_XOPMASK_VOP) {
			if (nmask & HAMMER2_XOPMASK_WAIT)
				wakeup(xop);
		}
		return;
	}

	/*
	 * All collectors are gone, we can cleanup and dispose of the XOP.
	 * Cleanup the collection cluster.
	 */
	/*
	 * Cleanup the xop's cluster.  If there is an inode reference,
	 * cache the cluster chains in the inode to improve performance,
	 * preventing them from recursively destroying the chain recursion.
	 *
	 * Note that ip->ccache[i] does NOT necessarily represent usable
	 * chains or chains that are related to the inode.  The chains are
	 * simply held to prevent bottom-up lastdrop destruction of
	 * potentially valuable resolved chain data.
	 */
	if (xop->ip1) {
		/*
		 * Cache cluster chains in a convenient inode.  The chains
		 * are cache ref'd but not held.  The inode simply serves
		 * as a place to cache the chains to prevent the chains
		 * from being cleaned up.
		 */
		ip = xop->ip1;
		hammer2_spin_ex(&ip->cluster_spin);
		prior_nchains = ip->ccache_nchains;
		for (i = 0; i < prior_nchains; ++i) {
			dropch[i] = ip->ccache[i].chain;
			ip->ccache[i].chain = NULL;
		}
		for (i = 0; i < xop->cluster.nchains; ++i) {
			ip->ccache[i] = xop->cluster.array[i];
			if (ip->ccache[i].chain)
				hammer2_chain_ref(ip->ccache[i].chain);
		}
		ip->ccache_nchains = i;
		hammer2_spin_unex(&ip->cluster_spin);

		/* Drop prior cache. */
		for (i = 0; i < prior_nchains; ++i) {
			chain = dropch[i];
			if (chain)
				hammer2_chain_drop(chain);
		}
	}
	/*
    * Drop and unhold chains in xop cluster
    */

	for (i = 0; i < xop->cluster.nchains; ++i) {
		xop->cluster.array[i].flags = 0;
		chain = xop->cluster.array[i].chain;
		if (chain) {
			xop->cluster.array[i].chain = NULL;
			hammer2_chain_drop_unhold(chain);
		}
	}

	/*
	 * Cleanup the fifos.  Since we are the only entity left on this
	 * xop we don't have to worry about fifo flow control.
	 */
	mask = xop->chk_mask;
	for (i = 0; mask && i < HAMMER2_MAXCLUSTER; ++i) {
		fifo = &xop->collect[i];
		while (fifo->ri != fifo->wi) {
			chain = fifo->array[fifo->ri & fifo_mask(xop)];
			if (chain)
				hammer2_chain_drop_unhold(chain);
			++fifo->ri;
		}
		mask &= ~(1U << i);
	}

	/* The inode is only held at this point, simply drop it. */
	if (xop->ip1) {
		hammer2_xop_unset_ipdep(xop->ip1);
		hammer2_inode_drop(xop->ip1);
		xop->ip1 = NULL;
	}
	if (xop->ip2) {
		hammer2_xop_unset_ipdep(xop->ip2);
		hammer2_inode_drop(xop->ip2);
		xop->ip2 = NULL;
	}
	if (xop->ip3) {
		if (xop->ip3 && xop->ip3 != xop->ip1) /* rename */
			hammer2_xop_unset_ipdep(xop->ip3);
		hammer2_inode_drop(xop->ip3);
		xop->ip3 = NULL;
	}
	if (xop->ip4) {
		if (xop->ip4 && xop->ip4 != xop->ip2) /* rename */
			hammer2_xop_unset_ipdep(xop->ip4);
		hammer2_inode_drop(xop->ip4);
		xop->ip4 = NULL;
	}

	if (xop->name1) {
		hfree(xop->name1, M_HAMMER2, strlen(xop->name1) + 1);
		xop->name1 = NULL;
		xop->name1_len = 0;
	}
	if (xop->name2) {
		hfree(xop->name2, M_HAMMER2, strlen(xop->name2) + 1);
		xop->name2 = NULL;
		xop->name2_len = 0;
	}

	for (i = 0; i < xop->cluster.nchains; ++i) {
		fifo = &xop->collect[i];
		KKASSERT(fifo->array == NULL || xop->fifo_size > 0);
		KKASSERT(fifo->errors == NULL || xop->fifo_size > 0);
		hfree(fifo->array, M_HAMMER2,
		    xop->fifo_size * sizeof(hammer2_chain_t *));
		hfree(fifo->errors, M_HAMMER2, xop->fifo_size * sizeof(int));
	}

	if (xop->scratch)
		hfree(xop->scratch, M_HAMMER2, hammer2_get_logical());

	pool_put(&hammer2_pool_xops, xop);
}

/*
 * (Backend) Feed chain data.
 * The chain must be locked (either shared or exclusive).  The caller may
 * unlock and drop the chain on return.  This function will add an extra
 * ref and hold the chain's data for the pass-back.
 *
 * No xop lock is needed because we are only manipulating fields under
 * our direct control.
 *
 * Returns 0 on success and a HAMMER2 error code if sync is permanently
 * lost.  The caller retains a ref on the chain but by convention
 * the lock is typically inherited by the xop (caller loses lock).
 *
 * Returns non-zero on error.  In this situation the caller retains a
 * ref on the chain but loses the lock (we unlock here).
 */
int
hammer2_xop_feed(hammer2_xop_head_t *xop, hammer2_chain_t *chain, int clindex,
    int error)
{
	hammer2_xop_fifo_t *fifo;
	size_t old_fifo_size;
	uint64_t mask;

	/* Early termination (typically of xop_readir). */
	if (hammer2_xop_active(xop) == 0) {
		error = HAMMER2_ERROR_ABORTED;
		goto done;
	}

	/*
	 * Entry into the XOP collector.
	 * We own the fifo->wi for our clindex.
	 */
	fifo = &xop->collect[clindex];
	while (fifo->ri == fifo->wi - xop->fifo_size) {
		if ((xop->run_mask & HAMMER2_XOPMASK_VOP) == 0) {
			error = HAMMER2_ERROR_ABORTED;
			goto done;
		}
		old_fifo_size = xop->fifo_size;
		xop->fifo_size *= 2;
		hammer2_xop_fifo_alloc(fifo, xop->fifo_size, old_fifo_size);
	}

	if (chain)
		hammer2_chain_ref_hold(chain);
	if (error == 0 && chain)
		error = chain->error;
	fifo->errors[fifo->wi & fifo_mask(xop)] = error;
	fifo->array[fifo->wi & fifo_mask(xop)] = chain;
	cpu_ccfence();
	++fifo->wi;

	/*
	 * Signal that a result was fed and wake the frontend collector if it
	 * is blocked waiting for one.
	 */
	mask = atomic_fetchadd_64(&xop->run_mask, HAMMER2_XOPMASK_FEED);
	if (mask & HAMMER2_XOPMASK_WAIT) {
		atomic_clear_64(&xop->run_mask, HAMMER2_XOPMASK_WAIT);
		wakeup(xop);
	}
	error = 0;
done:
	return (error);
}

/*
 * (Frontend) collect a response from a running cluster op.
 * Responses are collected into a cohesive response >= collect_key.
 *
 * Returns 0 on success plus a filled out xop->cluster structure.
 * Return ENOENT on normal termination.
 * Otherwise return an error.
 */
int
hammer2_xop_collect(hammer2_xop_head_t *xop, int flags)
{
	hammer2_xop_fifo_t *fifo;
	hammer2_chain_t *chain;
	hammer2_key_t lokey;
	uint64_t mask;
	int i, keynull, adv, error;

loop:
	/*
	 * First loop tries to advance pieces of the cluster which
	 * are out of sync.
	 */
	lokey = HAMMER2_KEY_MAX;
	keynull = HAMMER2_CHECK_NULL;
	mask = xop->run_mask;
	cpu_ccfence();

	for (i = 0; i < xop->cluster.nchains; ++i) {
		chain = xop->cluster.array[i].chain;
		if (chain == NULL) {
			adv = 1;
		} else if (chain->bref.key < xop->collect_key) {
			adv = 1;
		} else {
			keynull &= ~HAMMER2_CHECK_NULL;
			if (lokey > chain->bref.key)
				lokey = chain->bref.key;
			adv = 0;
		}
		if (adv == 0)
			continue;

		/* Advance element if possible, advanced element may be NULL. */
		if (chain)
			hammer2_chain_drop_unhold(chain);

		fifo = &xop->collect[i];
		if (fifo->ri != fifo->wi) {
			chain = fifo->array[fifo->ri & fifo_mask(xop)];
			error = fifo->errors[fifo->ri & fifo_mask(xop)];
			++fifo->ri;
			xop->cluster.array[i].chain = chain;
			xop->cluster.array[i].error = error;
			if (chain == NULL)
				xop->cluster.array[i].flags |=
				    HAMMER2_CITEM_NULL;
			--i; /* Loop on same index. */
		} else {
			/*
			 * Retain CITEM_NULL flag.  If set just repeat EOF.
			 * If not, the NULL,0 combination indicates an
			 * operation in-progress.
			 */
			xop->cluster.array[i].chain = NULL;
			/* Retain any CITEM_NULL setting. */
		}
	}

	/*
	 * Determine whether the lowest collected key meets clustering
	 * requirements.  Returns HAMMER2_ERROR_*:
	 *
	 * 0	  - key valid, cluster can be returned.
	 * ENOENT - normal end of scan, return ENOENT.
	 * EIO	  - IO error or CRC check error from hammer2_cluster_check().
	 */
	/*
	 * If WAITALL is requested we must wait for every node to finish before
	 * evaluating; otherwise check the cluster now.
	 */
	if ((flags & HAMMER2_XOP_COLLECT_WAITALL) &&
	    (mask & HAMMER2_XOPMASK_ALLDONE) != HAMMER2_XOPMASK_VOP) {
		error = HAMMER2_ERROR_EINPROGRESS;
	} else {
		error = hammer2_cluster_check(&xop->cluster, lokey, keynull);
	}

	/*
	 * Insufficient nodes have fed -- block until a backend feeds a result
	 * (feed clears WAIT and wakes us), then re-scan.  NOWAIT callers (e.g.
	 * strategy) return EINPROGRESS instead of blocking.
	 */
	if (error == HAMMER2_ERROR_EINPROGRESS) {
		if (flags & HAMMER2_XOP_COLLECT_NOWAIT)
			goto done;
		tsleep_interlock(xop, 0);
		if (atomic_cmpset_64(&xop->run_mask, mask,
		    mask | HAMMER2_XOPMASK_WAIT)) {
			/*
			 * 1s (not DragonFly's 60s): OpenBSD's tsleep_interlock
			 * is a no-op, so a wakeup lost in the cmpset->tsleep
			 * window costs one timeout period -- keep it short.
			 */
			tsleep(xop, PINTERLOCKED, "h2coll", hz);
		}
		goto loop;
	}

	/*
	 * Quorum agrees lokey is not a valid element; skip it and continue.
	 */
	if (error == HAMMER2_ERROR_ESRCH) {
		if (lokey != HAMMER2_KEY_MAX) {
			xop->collect_key = lokey + 1;
			goto loop;
		}
		error = HAMMER2_ERROR_ENOENT;
	}

	/*
	 * No quorum agreement (repair needed); advance and retry.
	 */
	if (error == HAMMER2_ERROR_EDEADLK) {
		if (lokey != HAMMER2_KEY_MAX) {
			xop->collect_key = lokey + 1;
			goto loop;
		}
	}

	if (lokey == HAMMER2_KEY_MAX)
		xop->collect_key = lokey;
	else
		xop->collect_key = lokey + 1;
done:
	return (error);
}

/*
 * ===========================================================================
 * XOP BACKEND HELPER THREADS
 *
 * Ported from DragonFly hammer2_admin.c.  DragonFly runs every XOP on these
 * per-(node,group) worker threads so a dead or stalled cluster node cannot
 * stall the frontend.  The whole fifo/collect/run_mask machinery exists to
 * serve them.
 *
 * PHASE 1: these threads are created (for mounted PFSs and any cluster with
 * nchains >= 2) but hammer2_xop_start_except still dispatches SYNCHRONOUSLY,
 * so the per-thread xopq stays empty and the threads simply idle.  Phase 2
 * flips the dispatch to enqueue+signal.  This lets the thread lifecycle be
 * verified against the working single-node path before the behavioral switch.
 * ===========================================================================
 */

int hammer2_xop_nthreads = 2;		/* helper threads per cluster node */

#define XOP_HASH_SIZE	16
#define XOP_HASH_MASK	(XOP_HASH_SIZE - 1)

static __inline int
xop_testhash(hammer2_thread_t *thr, hammer2_inode_t *ip, uint32_t *hash)
{
	uint32_t mask;
	int hv;

	hv = (int)((uintptr_t)ip + (uintptr_t)thr) / sizeof(hammer2_inode_t);
	mask = 1U << (hv & 31);
	hv >>= 5;
	return ((int)(hash[hv & XOP_HASH_MASK] & mask));
}

static __inline void
xop_sethash(hammer2_thread_t *thr, hammer2_inode_t *ip, uint32_t *hash)
{
	uint32_t mask;
	int hv;

	hv = (int)((uintptr_t)ip + (uintptr_t)thr) / sizeof(hammer2_inode_t);
	mask = 1U << (hv & 31);
	hv >>= 5;
	hash[hv & XOP_HASH_MASK] |= mask;
}

/*
 * Locate and return the next runnable xop for this thread's cluster index,
 * or NULL.  Leaves it on the queue (it blocks dependent xops) and sets
 * HAMMER2_XOP_FIFO_RUN on the returned xop.
 */
static hammer2_xop_head_t *
hammer2_xop_next(hammer2_thread_t *thr)
{
	hammer2_pfs_t *pmp = thr->pmp;
	int clindex = thr->clindex;
	uint32_t hash[XOP_HASH_SIZE] = { 0 };
	hammer2_xop_head_t *xop;

	hammer2_spin_ex(&pmp->xop_spin);
	TAILQ_FOREACH(xop, &thr->xopq, collect[clindex].entry) {
		/* Skip xops that depend on an already-selected inode. */
		if (xop_testhash(thr, xop->ip1, hash) ||
		    (xop->ip2 && xop_testhash(thr, xop->ip2, hash)) ||
		    (xop->ip3 && xop_testhash(thr, xop->ip3, hash)) ||
		    (xop->ip4 && xop_testhash(thr, xop->ip4, hash))) {
			continue;
		}
		xop_sethash(thr, xop->ip1, hash);
		if (xop->ip2)
			xop_sethash(thr, xop->ip2, hash);
		if (xop->ip3)
			xop_sethash(thr, xop->ip3, hash);
		if (xop->ip4)
			xop_sethash(thr, xop->ip4, hash);

		if (xop->collect[clindex].flags & HAMMER2_XOP_FIFO_RUN)
			continue;

		atomic_set_int(&xop->collect[clindex].flags,
		    HAMMER2_XOP_FIFO_RUN);
		break;
	}
	hammer2_spin_unex(&pmp->xop_spin);

	return (xop);
}

/*
 * Remove a completed xop from the thread's queue, clear FIFO_RUN.
 */
static void
hammer2_xop_dequeue(hammer2_thread_t *thr, hammer2_xop_head_t *xop)
{
	hammer2_pfs_t *pmp = thr->pmp;
	int clindex = thr->clindex;

	hammer2_spin_ex(&pmp->xop_spin);
	TAILQ_REMOVE(&thr->xopq, xop, collect[clindex].entry);
	atomic_clear_int(&xop->collect[clindex].flags, HAMMER2_XOP_FIFO_RUN);
	hammer2_spin_unex(&pmp->xop_spin);
	if (TAILQ_FIRST(&thr->xopq))
		hammer2_thr_signal(thr, HAMMER2_THREAD_XOPQ);
}

/*
 * Primary per-(node,group) xop worker thread.  Pulls xops queued for its
 * cluster index, runs the desc's storage_func on that single node, and
 * retires its bit.  (Phase 1: frontend never enqueues, so this idles.)
 */
void
hammer2_primary_xops_thread(void *arg)
{
	hammer2_thread_t *thr = arg;
	hammer2_xop_head_t *xop;
	uint64_t mask;
	uint32_t flags;
	uint32_t nflags;

	mask = 1LLU << thr->clindex;
	hprintf("xops_thread ENTER clindex=%d repidx=%d flags=%08x\n",
	    thr->clindex, thr->repidx, thr->flags);

	for (;;) {
		flags = thr->flags;
		cpu_ccfence();

		if (flags & HAMMER2_THREAD_STOP) {
			hprintf("xops_thread EXIT clindex=%d repidx=%d\n",
			    thr->clindex, thr->repidx);
			break;
		}

		if (flags & HAMMER2_THREAD_FREEZE) {
			hammer2_thr_signal2(thr, HAMMER2_THREAD_FROZEN,
			    HAMMER2_THREAD_FREEZE);
			continue;
		}
		if (flags & HAMMER2_THREAD_UNFREEZE) {
			hammer2_thr_signal2(thr, 0,
			    HAMMER2_THREAD_FROZEN | HAMMER2_THREAD_UNFREEZE);
			continue;
		}
		if (flags & HAMMER2_THREAD_FROZEN) {
			hammer2_thr_wait_any(thr,
			    HAMMER2_THREAD_UNFREEZE | HAMMER2_THREAD_STOP, 0);
			continue;
		}
		if (flags & HAMMER2_THREAD_REMASTER) {
			hammer2_thr_signal2(thr, 0, HAMMER2_THREAD_REMASTER);
			continue;
		}

		if (flags & HAMMER2_THREAD_XOPQ) {
			nflags = flags & ~HAMMER2_THREAD_XOPQ;
			if (!atomic_cmpset_int(&thr->flags, flags, nflags))
				continue;
			flags = nflags;
		}
		while ((xop = hammer2_xop_next(thr)) != NULL) {
			if (hammer2_xop_active(xop)) {
				xop->desc->storage_func((hammer2_xop_t *)xop,
				    thr->scratch, thr->clindex);
				hammer2_xop_dequeue(thr, xop);
				hammer2_xop_retire(xop, mask);
			} else {
				hammer2_xop_feed(xop, NULL, thr->clindex,
				    ECONNABORTED);
				hammer2_xop_dequeue(thr, xop);
				hammer2_xop_retire(xop, mask);
			}
		}

		/* Wait for work (poll every 30s as a backstop). */
		nflags = flags | HAMMER2_THREAD_WAITING;
		tsleep_interlock(&thr->flags, 0);
		if (atomic_cmpset_int(&thr->flags, flags, nflags))
			tsleep(&thr->flags, PINTERLOCKED, "h2idle", hz * 30);
	}

	thr->td = NULL;
	hammer2_thr_signal(thr, HAMMER2_THREAD_STOPPED);
	/* thr may be invalid after this point. */
	kthread_exit(0);
}

/*
 * Create the per-node xop helper threads for a pmp.  Idempotent.  Callers
 * are serialized by the mount lock (hammer2_mntlk).
 */
void
hammer2_xop_helper_create(hammer2_pfs_t *pmp)
{
	int i;
	int j;

	hprintf("xop_helper_create: pmp=%p iroot=%p nchains=%d nthreads=%d\n",
	    pmp, pmp->iroot,
	    pmp->iroot ? pmp->iroot->cluster.nchains : -1,
	    hammer2_xop_nthreads);

	pmp->has_xop_threads = 1;
	if (pmp->xop_groups == NULL) {
		pmp->xop_groups = hmalloc(hammer2_xop_nthreads *
		    sizeof(hammer2_xop_group_t), M_HAMMER2, M_WAITOK | M_ZERO);
	}
	for (i = 0; i < pmp->iroot->cluster.nchains; ++i) {
		for (j = 0; j < hammer2_xop_nthreads; ++j) {
			if (pmp->xop_groups[j].thrs[i].td)
				continue;
			hammer2_thr_create(&pmp->xop_groups[j].thrs[i], pmp,
			    NULL, "h2xop", i, j, hammer2_primary_xops_thread);
		}
	}
}

/*
 * Tear down all xop helper threads for a pmp.
 */
void
hammer2_xop_helper_cleanup(hammer2_pfs_t *pmp)
{
	int i;
	int j;

	if (pmp->xop_groups == NULL) {
		KKASSERT(pmp->has_xop_threads == 0);
		return;
	}
	for (i = 0; i < HAMMER2_MAXCLUSTER; ++i) {
		for (j = 0; j < hammer2_xop_nthreads; ++j) {
			if (pmp->xop_groups[j].thrs[i].td)
				hammer2_thr_delete(&pmp->xop_groups[j].thrs[i]);
		}
	}
	pmp->has_xop_threads = 0;
	hfree(pmp->xop_groups, M_HAMMER2,
	    hammer2_xop_nthreads * sizeof(hammer2_xop_group_t));
	pmp->xop_groups = NULL;
}

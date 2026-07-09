/*
 * KDMSG kernel messaging engine, ported from DragonFlyBSD sys/kern/kern_dmsg.c.
 *
 * This provides the kernel side of the dmsg cluster messaging protocol used by
 * HAMMER2 (LNK_CONN / LNK_SPAN handshake, transaction state machine, and the
 * reader/writer service threads that pump the connection socket).
 *
 * Ported to OpenBSD.  The DragonFly primitives are provided by the compat
 * shims below so the state-machine code ports faithfully:
 *
 *	lockmgr(lk, LK_EXCLUSIVE/LK_RELEASE)	-> rw_enter_write/rw_exit_write
 *	lksleep(chan, lk, pri, wmesg, timo)	-> rwsleep()
 *	lockinit(lk, name, ...)			-> rw_init()
 *	kmalloc(sz, mmsg, flags)		-> malloc(sz, M_HAMMER2, flags)
 *	kfree(ptr, mmsg)			-> free(ptr, M_HAMMER2, 0)
 *	fp_read/fp_write/fp_shutdown		-> soreceive/sosend/soshutdown
 *	fdrop(fp)				-> FRELE(fp, curproc)
 *	lwkt_create/lwkt_exit			-> kthread_create/kthread_exit
 *	kdio_printf(iocom, level, ...)		-> printf(...)
 *
 * The kernel side does NOT implement link encryption (matching DragonFly's
 * kernel).  The userland "hammer2 service" authorizes the local plaintext
 * link via an /etc/hammer2/remote/<ip>.none file.
 */

#define KDMSG_CLUSTERCTL_UNUSED01	0x00000001
#define KDMSG_CLUSTERCTL_KILLRX		0x00000002 /* staged helper exit */
#define KDMSG_CLUSTERCTL_KILLTX		0x00000004 /* staged helper exit */
#define KDMSG_CLUSTERCTL_SLEEPING	0x00000008 /* interlocked w/msglk */

/*
 * Compat shims mapping DragonFly primitives onto OpenBSD.
 */
#ifndef LK_RELEASE
#define LK_RELEASE	0x0100UL
#endif

static struct socket *kdmsg_so(struct file *fp);

static __inline void
h2_lockmgr(struct rwlock *lk, u_long how)
{
	if (how == LK_RELEASE)
		rw_exit_write(lk);
	else
		rw_enter_write(lk);
}
#define lockmgr(lk, how)		h2_lockmgr((lk), (how))
#define lksleep(chan, lk, pri, wmesg, timo)				\
		rwsleep((chan), (lk), PWAIT, (wmesg), (timo))
#define lockinit(lk, name, a, b)	rw_init((lk), (name))

#define kmalloc(sz, mmsg, flags)	malloc((sz), M_HAMMER2, (flags))
/* Reference mmsg so callers that only pass iocom->mmsg don't warn unused. */
#define kfree(ptr, mmsg)						\
		do { (void)(mmsg); free((ptr), M_HAMMER2, 0); } while (0)

#define fdrop(fp)			FRELE((fp), curproc)
#define fp_shutdown(fp, how)		soshutdown(kdmsg_so(fp), (how))
#define lwkt_exit()			kthread_exit(0)

/* kdio_printf() drops the (iocom, level) debug arguments. */
#define kdio_printf(iocom, level, ...)	printf(__VA_ARGS__)

/*
 * Forward declarations
 */
static int kdmsg_msg_receive_handling(kdmsg_msg_t *msg);
static int kdmsg_state_msgrx(kdmsg_msg_t *msg);
static int kdmsg_state_msgtx(kdmsg_msg_t *msg);
static void kdmsg_state_cleanuprx(kdmsg_msg_t *msg);
static void kdmsg_state_cleanuptx(kdmsg_msg_t *msg);
static void kdmsg_subq_delete(kdmsg_state_t *state);
static void kdmsg_simulate_failure(kdmsg_state_t *state, int meto, int error);
static void kdmsg_state_abort(kdmsg_state_t *state);
static void kdmsg_state_dying(kdmsg_state_t *state);
static void kdmsg_state_free(kdmsg_state_t *state);
static void kdmsg_state_hold(kdmsg_state_t *state);
static void kdmsg_state_drop(kdmsg_state_t *state);
static void kdmsg_drain_msg(kdmsg_msg_t *msg);
static void kdmsg_msg_write_locked(kdmsg_iocom_t *iocom, kdmsg_msg_t *msg);

static void kdmsg_iocom_thread_rd(void *arg);
static void kdmsg_iocom_thread_wr(void *arg);
static int kdmsg_autorxmsg(kdmsg_msg_t *msg);
static int kdmsg_lnk_conn_reply(kdmsg_state_t *state, kdmsg_msg_t *msg);
static int kdmsg_lnk_span_reply(kdmsg_state_t *state, kdmsg_msg_t *msg);

RB_GENERATE(kdmsg_state_tree, kdmsg_state, rbnode, kdmsg_state_cmp);

/*
 * dmsg CRC helpers.  The dmsg protocol uses the iSCSI (Castagnoli) CRC32,
 * which is exactly what the kernel's iscsi_crc32 provides and what the
 * userland libdmsg service computes, so the two interoperate on the wire.
 */
uint32_t
kdmsg_icrc32(const void *buf, size_t size)
{
	return (iscsi_crc32(buf, size));
}

uint32_t
kdmsg_icrc32c(const void *buf, size_t size, uint32_t crc)
{
	return (iscsi_crc32_ext(buf, size, crc));
}

/*
 * Return the socket backing a cluster file pointer.
 */
static struct socket *
kdmsg_so(struct file *fp)
{
	return (fp != NULL ? (struct socket *)fp->f_data : NULL);
}

/*
 * Blocking read of exactly len bytes from the connection socket into buf.
 * Returns 0 on success, or an errno (EPIPE on EOF) on failure.
 */
static int
kdmsg_soread(struct socket *so, void *buf, size_t len)
{
	struct uio uio;
	struct iovec iov;
	int flags;
	int error;

	if (so == NULL)
		return (EPIPE);
	while (len > 0) {
		iov.iov_base = buf;
		iov.iov_len = len;
		uio.uio_iov = &iov;
		uio.uio_iovcnt = 1;
		uio.uio_offset = 0;
		uio.uio_resid = len;
		uio.uio_segflg = UIO_SYSSPACE;
		uio.uio_rw = UIO_READ;
		uio.uio_procp = curproc;
		flags = 0;

		error = soreceive(so, NULL, &uio, NULL, NULL, &flags, 0);
		if (error)
			return (error);
		if (uio.uio_resid == len)	/* nothing read -> EOF */
			return (EPIPE);
		buf = (char *)buf + (len - uio.uio_resid);
		len = uio.uio_resid;
	}
	return (0);
}

/*
 * Blocking write of exactly len bytes to the connection socket.
 */
static int
kdmsg_sowrite(struct socket *so, const void *buf, size_t len)
{
	struct uio uio;
	struct iovec iov;
	int error;

	if (so == NULL)
		return (EPIPE);
	while (len > 0) {
		iov.iov_base = (void *)(uintptr_t)buf;
		iov.iov_len = len;
		uio.uio_iov = &iov;
		uio.uio_iovcnt = 1;
		uio.uio_offset = 0;
		uio.uio_resid = len;
		uio.uio_segflg = UIO_SYSSPACE;
		uio.uio_rw = UIO_WRITE;
		uio.uio_procp = curproc;

		error = sosend(so, NULL, &uio, NULL, NULL, 0);
		if (error)
			return (error);
		if (uio.uio_resid == len)	/* made no progress */
			return (EPIPE);
		buf = (const char *)buf + (len - uio.uio_resid);
		len = uio.uio_resid;
	}
	return (0);
}

/*
 * fp_read/fp_write shims: exact-length blocking transfers over the socket.
 */
static int
fp_read(struct file *fp, void *buf, size_t len, size_t *residp,
    int blocking, int seg)
{
	int error;

	error = kdmsg_soread(kdmsg_so(fp), buf, len);
	if (residp)
		*residp = error ? len : 0;
	return (error);
}

static int
fp_write(struct file *fp, void *buf, size_t len, ssize_t *resp, int seg)
{
	int error;

	error = kdmsg_sowrite(kdmsg_so(fp), buf, len);
	if (resp)
		*resp = error ? 0 : (ssize_t)len;
	return (error);
}

/*
 * Initialize the roll-up communications structure for a network messaging
 * session.  This function does not install the socket.
 */
void
kdmsg_iocom_init(kdmsg_iocom_t *iocom, void *handle, uint32_t flags,
		 struct malloc_type *mmsg,
		 int (*rcvmsg)(kdmsg_msg_t *msg))
{
	bzero(iocom, sizeof(*iocom));
	iocom->handle = handle;
	iocom->mmsg = mmsg;
	iocom->rcvmsg = rcvmsg;
	iocom->flags = flags;
	lockinit(&iocom->msglk, "h2msg", 0, 0);
	TAILQ_INIT(&iocom->msgq);
	RB_INIT(&iocom->staterd_tree);
	RB_INIT(&iocom->statewr_tree);

	iocom->state0.iocom = iocom;
	iocom->state0.parent = &iocom->state0;
	iocom->state0.refs = 1;		/* persistent root state */
	TAILQ_INIT(&iocom->state0.subq);
}

/*
 * [Re]connect using the passed file pointer.  The caller must ref the
 * fp for us.  We own that ref now.
 */
void
kdmsg_iocom_reconnect(kdmsg_iocom_t *iocom, struct file *fp,
		      const char *subsysname)
{
	/*
	 * Destroy the current connection
	 */
	lockmgr(&iocom->msglk, LK_EXCLUSIVE);
	atomic_set_int(&iocom->msg_ctl, KDMSG_CLUSTERCTL_KILLRX);
	while (iocom->msgrd_td || iocom->msgwr_td) {
		wakeup(&iocom->msg_ctl);
		lksleep(iocom, &iocom->msglk, 0, "clstrkl", hz);
	}

	/*
	 * Drop communications descriptor
	 */
	if (iocom->msg_fp) {
		fdrop(iocom->msg_fp);
		iocom->msg_fp = NULL;
	}

	/*
	 * Setup new communications descriptor
	 */
	iocom->msg_ctl = 0;
	iocom->msg_fp = fp;
	iocom->msg_seq = 0;
	iocom->flags &= ~KDMSG_IOCOMF_EXITNOACC;

	kthread_create(kdmsg_iocom_thread_rd, iocom, &iocom->msgrd_td,
		       subsysname);
	kthread_create(kdmsg_iocom_thread_wr, iocom, &iocom->msgwr_td,
		       subsysname);
	lockmgr(&iocom->msglk, LK_RELEASE);
}

/*
 * Caller sets up iocom->auto_lnk_conn and iocom->auto_lnk_span, then calls
 * this function to handle the state machine for LNK_CONN and LNK_SPAN.
 */
void
kdmsg_iocom_autoinitiate(kdmsg_iocom_t *iocom,
			 void (*auto_callback)(kdmsg_msg_t *msg))
{
	kdmsg_msg_t *msg;

	iocom->auto_callback = auto_callback;

	msg = kdmsg_msg_alloc(&iocom->state0,
			      DMSG_LNK_CONN | DMSGF_CREATE,
			      kdmsg_lnk_conn_reply, NULL);
	iocom->auto_lnk_conn.head = msg->any.head;
	msg->any.lnk_conn = iocom->auto_lnk_conn;
	iocom->conn_state = msg->state;
	kdmsg_state_hold(msg->state);	/* iocom->conn_state */
	printf("DMSGTRACE autoinit cmd=%08x\n", msg->any.head.cmd);
	kdmsg_msg_write(msg);
}

static int
kdmsg_lnk_conn_reply(kdmsg_state_t *state, kdmsg_msg_t *msg)
{
	kdmsg_iocom_t *iocom = state->iocom;
	kdmsg_msg_t *rmsg;

	/*
	 * Upon receipt of the LNK_CONN acknowledgement initiate an
	 * automatic SPAN if we were asked to.  Used by e.g. xdisk, but
	 * not used by HAMMER2 which must manage more than one transmitted
	 * SPAN.
	 */
	if ((msg->any.head.cmd & DMSGF_CREATE) &&
	    (iocom->flags & KDMSG_IOCOMF_AUTOTXSPAN)) {
		rmsg = kdmsg_msg_alloc(&iocom->state0,
				       DMSG_LNK_SPAN | DMSGF_CREATE,
				       kdmsg_lnk_span_reply, NULL);
		iocom->auto_lnk_span.head = rmsg->any.head;
		rmsg->any.lnk_span = iocom->auto_lnk_span;
		kdmsg_msg_write(rmsg);
	}

	/*
	 * Process shim after the CONN is acknowledged and before the CONN
	 * transaction is deleted.
	 */
	if (iocom->auto_callback)
		iocom->auto_callback(msg);

	if ((state->txcmd & DMSGF_DELETE) == 0 &&
	    (msg->any.head.cmd & DMSGF_DELETE)) {
		if (iocom->conn_state)
			kdmsg_state_drop(iocom->conn_state);
		iocom->conn_state = NULL;
		kdmsg_msg_reply(msg, 0);
	}

	return (0);
}

static int
kdmsg_lnk_span_reply(kdmsg_state_t *state, kdmsg_msg_t *msg)
{
	/*
	 * Be sure to process shim before terminating the SPAN transaction.
	 */
	if (state->iocom->auto_callback)
		state->iocom->auto_callback(msg);

	if ((state->txcmd & DMSGF_DELETE) == 0 &&
	    (msg->any.head.cmd & DMSGF_DELETE)) {
		kdmsg_msg_reply(msg, 0);
	}
	return (0);
}

/*
 * Disconnect and clean up
 */
void
kdmsg_iocom_uninit(kdmsg_iocom_t *iocom)
{
	kdmsg_state_t *state;
	kdmsg_msg_t *msg;
	int retries;

	/*
	 * Ask the cluster controller to go away by setting KILLRX.  Send a
	 * PING to get a response to unstick reading from the pipe.  After 10
	 * seconds shitcan the pipe and do an unclean shutdown.
	 */
	lockmgr(&iocom->msglk, LK_EXCLUSIVE);

	atomic_set_int(&iocom->msg_ctl, KDMSG_CLUSTERCTL_KILLRX);
	msg = kdmsg_msg_alloc(&iocom->state0, DMSG_LNK_PING, NULL, NULL);
	kdmsg_msg_write_locked(iocom, msg);

	retries = 10;
	while (iocom->msgrd_td || iocom->msgwr_td) {
		wakeup(&iocom->msg_ctl);
		lksleep(iocom, &iocom->msglk, 0, "clstrkl", hz);
		if (--retries == 0 && iocom->msg_fp) {
			kdio_printf(iocom, 0, "%s\n",
				    "iocom_uninit: shitcanning "
				    "unresponsive pipe");
			fp_shutdown(iocom->msg_fp, SHUT_RDWR);
		}
	}

	/*
	 * Cleanup caches
	 */
	if ((state = iocom->freerd_state) != NULL) {
		iocom->freerd_state = NULL;
		kdmsg_state_drop(state);
	}
	if ((state = iocom->freewr_state) != NULL) {
		iocom->freewr_state = NULL;
		kdmsg_state_drop(state);
	}

	/*
	 * Drop communications descriptor
	 */
	if (iocom->msg_fp) {
		fdrop(iocom->msg_fp);
		iocom->msg_fp = NULL;
	}
	lockmgr(&iocom->msglk, LK_RELEASE);
}

/*
 * Cluster controller thread.  Perform messaging functions.  We have one
 * thread for the reader and one for the writer.  The writer handles shutdown
 * requests (which should break the reader thread).
 */
static void
kdmsg_iocom_thread_rd(void *arg)
{
	kdmsg_iocom_t *iocom = arg;
	dmsg_hdr_t hdr;
	kdmsg_msg_t *msg = NULL;
	size_t hbytes;
	size_t abytes;
	int error = 0;

	while ((iocom->msg_ctl & KDMSG_CLUSTERCTL_KILLRX) == 0) {
		/*
		 * Retrieve the message from the pipe or socket.
		 */
		error = fp_read(iocom->msg_fp, &hdr, sizeof(hdr),
				NULL, 1, UIO_SYSSPACE);
		if (error)
			break;
		if (hdr.magic != DMSG_HDR_MAGIC) {
			kdio_printf(iocom, 1, "bad magic: %04x\n", hdr.magic);
			error = EINVAL;
			break;
		}
		printf("DMSGTRACE RD magic=%04x cmd=%08x\n", hdr.magic, hdr.cmd);
		hbytes = (hdr.cmd & DMSGF_SIZE) * DMSG_ALIGN;
		if (hbytes < sizeof(hdr) || hbytes > DMSG_HDR_MAX) {
			kdio_printf(iocom, 1, "bad header size %zu\n", hbytes);
			error = EINVAL;
			break;
		}

		/* XXX messy: mask cmd to avoid allocating state */
		msg = kdmsg_msg_alloc(&iocom->state0,
				      hdr.cmd & DMSGF_BASECMDMASK,
				      NULL, NULL);
		msg->any.head = hdr;
		msg->hdr_size = hbytes;
		if (hbytes > sizeof(hdr)) {
			error = fp_read(iocom->msg_fp, &msg->any.head + 1,
					hbytes - sizeof(hdr),
					NULL, 1, UIO_SYSSPACE);
			if (error) {
				kdio_printf(iocom, 1, "%s\n",
					    "short msg received");
				error = EINVAL;
				break;
			}
		}
		msg->aux_size = hdr.aux_bytes;
		if (msg->aux_size > DMSG_AUX_MAX) {
			kdio_printf(iocom, 1,
				    "illegal msg payload size %zu\n",
				    msg->aux_size);
			error = EINVAL;
			break;
		}
		if (msg->aux_size) {
			abytes = DMSG_DOALIGN(msg->aux_size);
			msg->aux_data = kmalloc(abytes, iocom->mmsg, M_WAITOK);
			msg->flags |= KDMSG_FLAG_AUXALLOC;
			error = fp_read(iocom->msg_fp, msg->aux_data,
					abytes, NULL, 1, UIO_SYSSPACE);
			if (error) {
				kdio_printf(iocom, 1, "%s\n",
					    "short msg payload received");
				break;
			}
		}

		error = kdmsg_msg_receive_handling(msg);
		msg = NULL;
	}

	lockmgr(&iocom->msglk, LK_EXCLUSIVE);
	if (msg)
		kdmsg_msg_free(msg);

	/*
	 * Shutdown the socket and set KILLRX for consistency in case the
	 * shutdown was not commanded.  Signal the transmit side to shutdown
	 * by setting KILLTX and waking it up.
	 */
	if (iocom->msg_fp)
		fp_shutdown(iocom->msg_fp, SHUT_RDWR);
	atomic_set_int(&iocom->msg_ctl, KDMSG_CLUSTERCTL_KILLRX |
					KDMSG_CLUSTERCTL_KILLTX);
	iocom->msgrd_td = NULL;
	lockmgr(&iocom->msglk, LK_RELEASE);
	wakeup(&iocom->msg_ctl);

	/*
	 * iocom can be ripped out at any time once the lock is released with
	 * msgrd_td set to NULL.  The wakeup()s are safe but that is all.
	 */
	wakeup(iocom);
	lwkt_exit();
}

static void
kdmsg_iocom_thread_wr(void *arg)
{
	kdmsg_iocom_t *iocom = arg;
	kdmsg_msg_t *msg;
	ssize_t res;
	size_t abytes;
	int error = 0;
	int save_ticks;
	int didwarn;

	/*
	 * Transmit loop
	 */
	msg = NULL;
	lockmgr(&iocom->msglk, LK_EXCLUSIVE);

	while ((iocom->msg_ctl & KDMSG_CLUSTERCTL_KILLTX) == 0 && error == 0) {
		/*
		 * Sleep if no messages pending.  Interlock with flag while
		 * holding msglk.
		 */
		if (TAILQ_EMPTY(&iocom->msgq)) {
			atomic_set_int(&iocom->msg_ctl,
				       KDMSG_CLUSTERCTL_SLEEPING);
			lksleep(&iocom->msg_ctl, &iocom->msglk, 0, "msgwr", hz);
			atomic_clear_int(&iocom->msg_ctl,
					 KDMSG_CLUSTERCTL_SLEEPING);
		}

		while ((msg = TAILQ_FIRST(&iocom->msgq)) != NULL) {
			/*
			 * Remove msg from the transmit queue and do persist
			 * and half-closed state handling.
			 */
			TAILQ_REMOVE(&iocom->msgq, msg, qentry);

			error = kdmsg_state_msgtx(msg);
			if (error == EALREADY) {
				error = 0;
				kdmsg_msg_free(msg);
				continue;
			}
			if (error) {
				kdmsg_msg_free(msg);
				break;
			}

			/*
			 * Dump the message to the pipe or socket.  We have to
			 * clean up the message as if the transmit succeeded
			 * even if it failed.
			 */
			lockmgr(&iocom->msglk, LK_RELEASE);
			error = fp_write(iocom->msg_fp, &msg->any,
					 msg->hdr_size, &res, UIO_SYSSPACE);
			printf("DMSGTRACE WR cmd=%08x hdr=%zu err=%d res=%zd\n", msg->any.head.cmd, (size_t)msg->hdr_size, error, (ssize_t)res);
			if (error || res != (ssize_t)msg->hdr_size) {
				if (error == 0)
					error = EINVAL;
				lockmgr(&iocom->msglk, LK_EXCLUSIVE);
				kdmsg_state_cleanuptx(msg);
				break;
			}
			if (msg->aux_size) {
				abytes = DMSG_DOALIGN(msg->aux_size);
				error = fp_write(iocom->msg_fp,
						 msg->aux_data, abytes,
						 &res, UIO_SYSSPACE);
				if (error || res != (ssize_t)abytes) {
					if (error == 0)
						error = EINVAL;
					lockmgr(&iocom->msglk, LK_EXCLUSIVE);
					kdmsg_state_cleanuptx(msg);
					break;
				}
			}
			lockmgr(&iocom->msglk, LK_EXCLUSIVE);
			kdmsg_state_cleanuptx(msg);
		}
	}

	/*
	 * Shutdown the socket and set KILLTX for consistency in case the
	 * shutdown was not commanded.  Signal the receive side to shutdown by
	 * setting KILLRX and waking it up.
	 */
	if (iocom->msg_fp)
		fp_shutdown(iocom->msg_fp, SHUT_RDWR);
	atomic_set_int(&iocom->msg_ctl, KDMSG_CLUSTERCTL_KILLRX |
					KDMSG_CLUSTERCTL_KILLTX);
	wakeup(&iocom->msg_ctl);

	/*
	 * The transmit thread is responsible for final cleanups, wait for the
	 * receive side to terminate to prevent new received states from
	 * interfering with our cleanup.
	 *
	 * Do not set msgwr_td to NULL until we actually exit.
	 */
	while (iocom->msgrd_td) {
		wakeup(&iocom->msg_ctl);
		lksleep(iocom, &iocom->msglk, 0, "clstrkt", hz);
	}

	/*
	 * We can no longer receive new messages.  We must drain the transmit
	 * message queue and simulate received messages to close any remaining
	 * states.
	 */
	save_ticks = ticks;
	didwarn = 0;
	iocom->flags |= KDMSG_IOCOMF_EXITNOACC;

	while (TAILQ_FIRST(&iocom->msgq) ||
	       RB_ROOT(&iocom->staterd_tree) ||
	       RB_ROOT(&iocom->statewr_tree) ||
	       iocom->conn_state) {
		kdmsg_drain_msgq(iocom);
		kdmsg_simulate_failure(&iocom->state0, 0, DMSG_ERR_LOSTLINK);
		lksleep(iocom, &iocom->msglk, 0, "clstrtk", hz / 2);

		if ((int)(ticks - save_ticks) > hz*60) {
			kdio_printf(iocom, 0, "Can't terminate: msgq %p "
				    "rd_tree %p wr_tree %p\n",
				    TAILQ_FIRST(&iocom->msgq),
				    RB_ROOT(&iocom->staterd_tree),
				    RB_ROOT(&iocom->statewr_tree));
			lksleep(iocom, &iocom->msglk, 0, "clstrtk", hz * 10);
		}
		(void)didwarn;
	}

	lockmgr(&iocom->msglk, LK_RELEASE);

	KKASSERT(RB_EMPTY(&iocom->staterd_tree));
	KKASSERT(RB_EMPTY(&iocom->statewr_tree));
	KKASSERT(iocom->conn_state == NULL);

	if (iocom->exit_func) {
		iocom->msgwr_td = NULL;
		iocom->exit_func(iocom);
	} else {
		iocom->msgwr_td = NULL;
		wakeup(iocom);
	}
	lwkt_exit();
}

/*
 * This cleans out the pending transmit message queue, adjusting any
 * persistent states properly in the process.  Called with iocom locked.
 */
void
kdmsg_drain_msgq(kdmsg_iocom_t *iocom)
{
	kdmsg_msg_t *msg;

	while ((msg = TAILQ_FIRST(&iocom->msgq)) != NULL) {
		TAILQ_REMOVE(&iocom->msgq, msg, qentry);
		kdmsg_drain_msg(msg);
	}
}

/*
 * Drain one message by simulating transmission and also simulating a receive
 * failure.
 */
static void
kdmsg_drain_msg(kdmsg_msg_t *msg)
{
	if (kdmsg_state_msgtx(msg)) {
		kdmsg_msg_free(msg);
	} else {
		if (msg->state) {
			kdmsg_simulate_failure(msg->state,
					       0, DMSG_ERR_LOSTLINK);
		}
		kdmsg_state_cleanuptx(msg);
	}
}

/*
 * Do all processing required to handle a freshly received message after its
 * low level header has been validated.  iocom is not locked.
 */
static int
kdmsg_msg_receive_handling(kdmsg_msg_t *msg)
{
	kdmsg_iocom_t *iocom = msg->state->iocom;
	int error;

	/*
	 * State machine tracking, state assignment for msg, returns error and
	 * discard status.  Errors are fatal to the connection except for
	 * EALREADY which forces a discard without execution.
	 */
	error = kdmsg_state_msgrx(msg);
	if (error) {
		kdmsg_msg_free(msg);
		if (error == EALREADY)
			error = 0;
	} else if (msg->state && msg->state->func) {
		/*
		 * Message related to state which already has a handling
		 * function installed for it.
		 */
		error = msg->state->func(msg->state, msg);
		kdmsg_state_cleanuprx(msg);
	} else if (iocom->flags & KDMSG_IOCOMF_AUTOANY) {
		error = kdmsg_autorxmsg(msg);
		kdmsg_state_cleanuprx(msg);
	} else {
		error = iocom->rcvmsg(msg);
		kdmsg_state_cleanuprx(msg);
	}
	return (error);
}

/*
 * Process state tracking for a message after reception and dequeueing, prior
 * to execution of the state callback.  msglk is not held.
 */
static int
kdmsg_state_msgrx(kdmsg_msg_t *msg)
{
	kdmsg_iocom_t *iocom = msg->state->iocom;
	kdmsg_state_t *state;
	kdmsg_state_t *pstate;
	kdmsg_state_t sdummy;
	int error;

	bzero(&sdummy, sizeof(sdummy));

	/*
	 * Make sure a state structure is ready to go in case we need a new
	 * one.  This is the only routine which uses freerd_state so no races
	 * are possible.
	 */
	if ((state = iocom->freerd_state) == NULL) {
		state = kmalloc(sizeof(*state), iocom->mmsg, M_WAITOK | M_ZERO);
		state->flags = KDMSG_STATE_DYNAMIC;
		state->iocom = iocom;
		state->refs = 1;
		TAILQ_INIT(&state->subq);
		iocom->freerd_state = state;
	}
	state = NULL;	/* safety */

	/*
	 * Lock RB tree and locate existing persistent state, if any.
	 *
	 * If received msg is a command state is on staterd_tree.
	 * If received msg is a reply state is on statewr_tree.
	 */
	lockmgr(&iocom->msglk, LK_EXCLUSIVE);

again:
	if (msg->state == &iocom->state0) {
		sdummy.msgid = msg->any.head.msgid;
		sdummy.iocom = iocom;
		if (msg->any.head.cmd & DMSGF_REVTRANS) {
			state = RB_FIND(kdmsg_state_tree, &iocom->statewr_tree,
					&sdummy);
		} else {
			state = RB_FIND(kdmsg_state_tree, &iocom->staterd_tree,
					&sdummy);
		}
		if (state == NULL)
			state = &iocom->state0;
		if (state->flags & KDMSG_STATE_INTERLOCK) {
			state->flags |= KDMSG_STATE_SIGNAL;
			lksleep(state, &iocom->msglk, 0, "dmrace", hz);
			goto again;
		}
		kdmsg_state_hold(state);
		kdmsg_state_drop(msg->state);	/* iocom->state0 */
		msg->state = state;
	} else {
		state = msg->state;
	}

	/*
	 * Short-cut one-off or mid-stream messages.
	 */
	if ((msg->any.head.cmd & (DMSGF_CREATE | DMSGF_DELETE |
				  DMSGF_ABORT)) == 0) {
		error = 0;
		goto done;
	}

	/*
	 * Switch on CREATE, DELETE, REPLY, and also handle ABORT from inside
	 * the case statements.
	 */
	switch(msg->any.head.cmd & (DMSGF_CREATE|DMSGF_DELETE|DMSGF_REPLY)) {
	case DMSGF_CREATE:
	case DMSGF_CREATE | DMSGF_DELETE:
		/*
		 * New persistant command received.
		 */
		if (state != &iocom->state0) {
			kdio_printf(iocom, 1, "%s\n", "duplicate transaction");
			error = EINVAL;
			break;
		}

		/*
		 * Lookup the circuit.  The circuit is an open transaction.
		 * The REVCIRC bit in the message tells us which side
		 * initiated the transaction representing the circuit.
		 */
		if (msg->any.head.circuit) {
			sdummy.msgid = msg->any.head.circuit;

			if (msg->any.head.cmd & DMSGF_REVCIRC) {
				pstate = RB_FIND(kdmsg_state_tree,
						 &iocom->statewr_tree,
						 &sdummy);
			} else {
				pstate = RB_FIND(kdmsg_state_tree,
						 &iocom->staterd_tree,
						 &sdummy);
			}
			if (pstate == NULL) {
				kdio_printf(iocom, 1, "%s\n",
					    "missing parent in stacked trans");
				error = EINVAL;
				break;
			}
		} else {
			pstate = &iocom->state0;
		}

		/*
		 * Allocate new state.  msg->state becomes the owner of the ref
		 * we inherit from freerd_state.
		 */
		kdmsg_state_drop(state);
		state = iocom->freerd_state;
		iocom->freerd_state = NULL;

		msg->state = state;		/* inherits freerd ref */
		state->parent = pstate;
		KKASSERT(state->iocom == iocom);
		state->flags |= KDMSG_STATE_RBINSERTED |
				KDMSG_STATE_SUBINSERTED |
				KDMSG_STATE_OPPOSITE;
		if (TAILQ_EMPTY(&pstate->subq))
			kdmsg_state_hold(pstate);/* states on pstate->subq */
		kdmsg_state_hold(state);	/* state on pstate->subq */
		kdmsg_state_hold(state);	/* state on rbtree */
		state->icmd = msg->any.head.cmd & DMSGF_BASECMDMASK;
		state->rxcmd = msg->any.head.cmd & ~DMSGF_DELETE;
		state->txcmd = DMSGF_REPLY;
		state->msgid = msg->any.head.msgid;
		state->flags &= ~KDMSG_STATE_NEW;
		RB_INSERT(kdmsg_state_tree, &iocom->staterd_tree, state);
		TAILQ_INSERT_TAIL(&pstate->subq, state, entry);
		error = 0;
		break;
	case DMSGF_DELETE:
		/*
		 * Persistent state is expected but might not exist if an
		 * ABORT+DELETE races the close.
		 */
		if (state == &iocom->state0) {
			if (msg->any.head.cmd & DMSGF_ABORT) {
				error = EALREADY;
			} else {
				kdio_printf(iocom, 1, "%s\n",
					    "msgrx: no state for DELETE");
				error = EINVAL;
			}
			break;
		}
		if ((state->rxcmd & DMSGF_CREATE) == 0) {
			if (msg->any.head.cmd & DMSGF_ABORT) {
				error = EALREADY;
			} else {
				kdio_printf(iocom, 1, "%s\n",
					    "msgrx: state reused for DELETE");
				error = EINVAL;
			}
			break;
		}
		error = 0;
		break;
	default:
		/*
		 * Check for mid-stream ABORT command received, otherwise allow.
		 */
		if (msg->any.head.cmd & DMSGF_ABORT) {
			if (state == &iocom->state0 ||
			    (state->rxcmd & DMSGF_CREATE) == 0) {
				error = EALREADY;
				break;
			}
		}
		error = 0;
		break;
	case DMSGF_REPLY | DMSGF_CREATE:
	case DMSGF_REPLY | DMSGF_CREATE | DMSGF_DELETE:
		/*
		 * When receiving a reply with CREATE set the original
		 * persistent state message should already exist.
		 */
		if (state == &iocom->state0) {
			kdio_printf(iocom, 1, "msgrx: no state match for "
				    "REPLY cmd=%08x msgid=%016llx\n",
				    msg->any.head.cmd,
				    (unsigned long long)msg->any.head.msgid);
			error = EINVAL;
			break;
		}
		state->rxcmd = msg->any.head.cmd & ~DMSGF_DELETE;
		error = 0;
		break;
	case DMSGF_REPLY | DMSGF_DELETE:
		/*
		 * Received REPLY+ABORT+DELETE in case where msgid has already
		 * been fully closed, ignore the message.
		 */
		if (state == &iocom->state0) {
			if (msg->any.head.cmd & DMSGF_ABORT) {
				error = EALREADY;
			} else {
				kdio_printf(iocom, 1, "%s\n",
					    "msgrx: no state match "
					    "for REPLY|DELETE");
				error = EINVAL;
			}
			break;
		}
		if ((state->rxcmd & DMSGF_CREATE) == 0) {
			if (msg->any.head.cmd & DMSGF_ABORT) {
				error = EALREADY;
			} else {
				kdio_printf(iocom, 1, "%s\n",
					    "msgrx: state reused "
					    "for REPLY|DELETE");
				error = EINVAL;
			}
			break;
		}
		error = 0;
		break;
	case DMSGF_REPLY:
		/*
		 * Check for mid-stream ABORT reply received to sent command.
		 */
		if (msg->any.head.cmd & DMSGF_ABORT) {
			if (state == &iocom->state0 ||
			    (state->rxcmd & DMSGF_CREATE) == 0) {
				error = EALREADY;
				break;
			}
		}
		error = 0;
		break;
	}

	/*
	 * Calculate the easy-switch() transactional command.
	 */
done:
	if (msg->any.head.cmd & (DMSGF_CREATE | DMSGF_DELETE)) {
		if (state != &iocom->state0) {
			msg->tcmd = (msg->state->icmd & DMSGF_BASECMDMASK) |
				    (msg->any.head.cmd & (DMSGF_CREATE |
							  DMSGF_DELETE |
							  DMSGF_REPLY));
		} else {
			msg->tcmd = 0;
		}
	} else {
		msg->tcmd = msg->any.head.cmd & DMSGF_CMDSWMASK;
	}

	/*
	 * Adjust the state for DELETE handling now, before making the callback
	 * so we are atomic with other state updates.
	 */
	if ((state = msg->state) == NULL || error != 0) {
		kdio_printf(iocom, 1, "msgrx: state=%p error %d\n",
			    state, error);
	} else if (msg->any.head.cmd & DMSGF_DELETE) {
		KKASSERT((state->rxcmd & DMSGF_DELETE) == 0);
		state->rxcmd |= DMSGF_DELETE;
		if (state->txcmd & DMSGF_DELETE) {
			KKASSERT(state->flags & KDMSG_STATE_RBINSERTED);
			if (state->rxcmd & DMSGF_REPLY) {
				KKASSERT(msg->any.head.cmd & DMSGF_REPLY);
				RB_REMOVE(kdmsg_state_tree,
					  &iocom->statewr_tree, state);
			} else {
				KKASSERT((msg->any.head.cmd & DMSGF_REPLY) == 0);
				RB_REMOVE(kdmsg_state_tree,
					  &iocom->staterd_tree, state);
			}
			state->flags &= ~KDMSG_STATE_RBINSERTED;
			kdmsg_state_drop(state);	/* state on rbtree */
		}
	}
	lockmgr(&iocom->msglk, LK_RELEASE);

	return (error);
}

/*
 * Called instead of iocom->rcvmsg() if any of the AUTO flags are set.  This
 * routine must call iocom->rcvmsg() for anything not automatically handled.
 */
static int
kdmsg_autorxmsg(kdmsg_msg_t *msg)
{
	kdmsg_iocom_t *iocom = msg->state->iocom;
	kdmsg_msg_t *rep;
	int error = 0;
	uint32_t cmd;

	if (msg->state) {
		cmd = (msg->state->icmd & DMSGF_BASECMDMASK) |
		      (msg->any.head.cmd & (DMSGF_CREATE |
					    DMSGF_DELETE |
					    DMSGF_REPLY));
	} else {
		cmd = 0;
	}

	switch(cmd) {
	case DMSG_LNK_PING:
		/*
		 * Received ping, send reply
		 */
		rep = kdmsg_msg_alloc(msg->state, DMSG_LNK_PING | DMSGF_REPLY,
				      NULL, NULL);
		kdmsg_msg_write(rep);
		break;
	case DMSG_LNK_PING | DMSGF_REPLY:
		/* ignore replies */
		break;
	case DMSG_LNK_CONN | DMSGF_CREATE:
	case DMSG_LNK_CONN | DMSGF_CREATE | DMSGF_DELETE:
		/*
		 * Received LNK_CONN transaction.  Transmit response and leave
		 * transaction open, which allows the other end to start the
		 * SPAN protocol.
		 */
		if ((msg->any.head.cmd & DMSGF_DELETE) == 0) {
			if (iocom->flags & KDMSG_IOCOMF_AUTOCONN) {
				kdmsg_msg_result(msg, 0);
				if (iocom->auto_callback)
					iocom->auto_callback(msg);
			} else {
				error = iocom->rcvmsg(msg);
			}
			break;
		}
		/* fall through */
	case DMSG_LNK_CONN | DMSGF_DELETE:
		if (iocom->flags & KDMSG_IOCOMF_AUTOCONN) {
			if (iocom->auto_callback)
				iocom->auto_callback(msg);
			kdmsg_msg_reply(msg, 0);
		} else {
			error = iocom->rcvmsg(msg);
		}
		break;
	case DMSG_LNK_SPAN | DMSGF_CREATE:
	case DMSG_LNK_SPAN | DMSGF_CREATE | DMSGF_DELETE:
		/*
		 * Received LNK_SPAN transaction.  We do not have to respond
		 * (except on termination), but we must leave the transaction
		 * open.
		 */
		if (iocom->flags & KDMSG_IOCOMF_AUTORXSPAN) {
			if ((msg->any.head.cmd & DMSGF_DELETE) == 0) {
				if (iocom->auto_callback)
					iocom->auto_callback(msg);
				break;
			}
			/* fall through */
		} else {
			error = iocom->rcvmsg(msg);
			break;
		}
		/* fall through */
	case DMSG_LNK_SPAN | DMSGF_DELETE:
		if (iocom->flags & KDMSG_IOCOMF_AUTORXSPAN) {
			if (iocom->auto_callback)
				iocom->auto_callback(msg);
			kdmsg_msg_reply(msg, 0);
		} else {
			error = iocom->rcvmsg(msg);
		}
		break;
	default:
		error = iocom->rcvmsg(msg);
		break;
	}
	return (error);
}

/*
 * Post-receive-handling message and state cleanup.  Called after the state
 * function handling/callback.  msglk is not held.
 */
static void
kdmsg_state_cleanuprx(kdmsg_msg_t *msg)
{
	kdmsg_state_t *state = msg->state;
	kdmsg_iocom_t *iocom = state->iocom;

	lockmgr(&iocom->msglk, LK_EXCLUSIVE);
	if (state != &iocom->state0) {
		/*
		 * When terminating a transaction (in either direction), all
		 * sub-states are aborted.
		 */
		if ((msg->any.head.cmd & DMSGF_DELETE) &&
		    TAILQ_FIRST(&msg->state->subq)) {
			kdmsg_simulate_failure(msg->state,
					       0, DMSG_ERR_LOSTLINK);
		}

		/*
		 * Once the state is fully closed we can (try to) remove it
		 * from the subq topology.
		 */
		if ((state->flags & KDMSG_STATE_SUBINSERTED) &&
		    (state->rxcmd & DMSGF_DELETE) &&
		    (state->txcmd & DMSGF_DELETE)) {
			kdmsg_subq_delete(state);
		}
	}
	kdmsg_msg_free(msg);
	lockmgr(&iocom->msglk, LK_RELEASE);
}

/*
 * Remove state from its parent's subq.  This can wind up recursively dropping
 * the parent upward.
 */
static void
kdmsg_subq_delete(kdmsg_state_t *state)
{
	kdmsg_state_t *pstate;

	if (state->flags & KDMSG_STATE_SUBINSERTED) {
		pstate = state->parent;
		KKASSERT(pstate);
		if (pstate->scan == state)
			pstate->scan = NULL;
		TAILQ_REMOVE(&pstate->subq, state, entry);
		state->flags &= ~KDMSG_STATE_SUBINSERTED;
		state->parent = NULL;
		if (TAILQ_EMPTY(&pstate->subq)) {
			kdmsg_state_drop(pstate);/* pstate->subq */
		}
		pstate = NULL;			 /* safety */
		kdmsg_state_drop(state);	 /* pstate->subq */
	} else {
		KKASSERT(state->parent == NULL);
	}
}

/*
 * Simulate receiving a message which terminates an active transaction state.
 * Used when the other end of the link is dead so the device driver gets a
 * completed transaction for all pending states.  Called with iocom locked.
 */
static void
kdmsg_simulate_failure(kdmsg_state_t *state, int meto, int error)
{
	kdmsg_state_t *substate;

	kdmsg_state_hold(state);		/* aborting */

	if (meto)
		kdmsg_state_abort(state);

again:
	TAILQ_FOREACH(substate, &state->subq, entry) {
		if (substate->flags & KDMSG_STATE_ABORTING)
			continue;
		state->scan = substate;
		kdmsg_simulate_failure(substate, 1, error);
		if (state->scan != substate)
			goto again;
	}
	kdmsg_state_drop(state);		/* aborting */
}

static void
kdmsg_state_abort(kdmsg_state_t *state)
{
	kdmsg_msg_t *msg;

	KKASSERT((state->flags & KDMSG_STATE_ABORTING) == 0);
	if (state->flags & KDMSG_STATE_ABORTING)
		return;
	state->flags |= KDMSG_STATE_ABORTING;
	kdmsg_state_dying(state);
	if (state->flags & KDMSG_STATE_NEW)
		return;

	/*
	 * NOTE: We are simulating a received message using our state (vs a
	 *	 message generated by the other side using its state), so we
	 *	 must invert DMSGF_REVTRANS and DMSGF_REVCIRC.
	 */
	if ((state->rxcmd & DMSGF_DELETE) == 0) {
		msg = kdmsg_msg_alloc(state, DMSG_LNK_ERROR, NULL, NULL);
		if ((state->rxcmd & DMSGF_CREATE) == 0)
			msg->any.head.cmd |= DMSGF_CREATE;
		msg->any.head.cmd |= DMSGF_DELETE |
				     (state->rxcmd & DMSGF_REPLY);
		msg->any.head.cmd ^= (DMSGF_REVTRANS | DMSGF_REVCIRC);
		msg->any.head.error = DMSG_ERR_LOSTLINK;
		lockmgr(&state->iocom->msglk, LK_RELEASE);
		kdmsg_msg_receive_handling(msg);
		lockmgr(&state->iocom->msglk, LK_EXCLUSIVE);
		msg = NULL;
	}
}

/*
 * Recursively sets KDMSG_STATE_DYING on state and all sub-states, preventing
 * the transmission of any new messages on these states.
 */
static void
kdmsg_state_dying(kdmsg_state_t *state)
{
	kdmsg_state_t *scan;

	if ((state->flags & KDMSG_STATE_DYING) == 0) {
		state->flags |= KDMSG_STATE_DYING;
		TAILQ_FOREACH(scan, &state->subq, entry)
			kdmsg_state_dying(scan);
	}
}

/*
 * Process state tracking for a message prior to transmission.  Called with
 * msglk held and the msg dequeued.  Returns non-zero if the message is bad
 * and should be deleted by the caller.
 */
static int
kdmsg_state_msgtx(kdmsg_msg_t *msg)
{
	kdmsg_iocom_t *iocom = msg->state->iocom;
	kdmsg_state_t *state;
	int error;

	/*
	 * Make sure a state structure is ready to go in case we need a new
	 * one.  This is the only routine which uses freewr_state so no races
	 * are possible.
	 */
	if ((state = iocom->freewr_state) == NULL) {
		state = kmalloc(sizeof(*state), iocom->mmsg, M_WAITOK | M_ZERO);
		state->flags = KDMSG_STATE_DYNAMIC;
		state->iocom = iocom;
		state->refs = 1;
		TAILQ_INIT(&state->subq);
		iocom->freewr_state = state;
	}

	state = msg->state;

	/*
	 * Short-cut one-off or mid-stream messages (state may be NULL).
	 */
	if ((msg->any.head.cmd & (DMSGF_CREATE | DMSGF_DELETE |
				  DMSGF_ABORT)) == 0) {
		return (0);
	}

	switch(msg->any.head.cmd & (DMSGF_CREATE | DMSGF_DELETE |
				    DMSGF_REPLY)) {
	case DMSGF_CREATE:
	case DMSGF_CREATE | DMSGF_DELETE:
		KKASSERT(state != NULL);
		state->icmd = msg->any.head.cmd & DMSGF_BASECMDMASK;
		state->txcmd = msg->any.head.cmd & ~DMSGF_DELETE;
		state->rxcmd = DMSGF_REPLY;
		state->flags &= ~KDMSG_STATE_NEW;
		error = 0;
		break;
	case DMSGF_DELETE:
		if (state == &iocom->state0) {
			if (msg->any.head.cmd & DMSGF_ABORT) {
				error = EALREADY;
			} else {
				kdio_printf(iocom, 1, "msgtx: no state match "
					    "for DELETE cmd=%08x msgid=%016llx\n",
					    msg->any.head.cmd,
					    (unsigned long long)msg->any.head.msgid);
				error = EINVAL;
			}
			break;
		}
		if ((state->txcmd & DMSGF_CREATE) == 0) {
			if (msg->any.head.cmd & DMSGF_ABORT) {
				error = EALREADY;
			} else {
				kdio_printf(iocom, 1, "%s\n",
					    "msgtx: state reused for DELETE");
				error = EINVAL;
			}
			break;
		}
		error = 0;
		break;
	default:
		if (msg->any.head.cmd & DMSGF_ABORT) {
			if (state == &state->iocom->state0 ||
			    (state->txcmd & DMSGF_CREATE) == 0) {
				error = EALREADY;
				break;
			}
		}
		error = 0;
		break;
	case DMSGF_REPLY | DMSGF_CREATE:
	case DMSGF_REPLY | DMSGF_CREATE | DMSGF_DELETE:
		if (state == &state->iocom->state0) {
			kdio_printf(iocom, 1, "%s\n",
				    "msgtx: no state match for REPLY | CREATE");
			error = EINVAL;
			break;
		}
		state->txcmd = msg->any.head.cmd & ~DMSGF_DELETE;
		error = 0;
		break;
	case DMSGF_REPLY | DMSGF_DELETE:
		if (state == &state->iocom->state0) {
			if (msg->any.head.cmd & DMSGF_ABORT) {
				error = EALREADY;
			} else {
				kdio_printf(iocom, 1, "%s\n",
					    "msgtx: no state match "
					    "for REPLY | DELETE");
				error = EINVAL;
			}
			break;
		}
		if ((state->txcmd & DMSGF_CREATE) == 0) {
			if (msg->any.head.cmd & DMSGF_ABORT) {
				error = EALREADY;
			} else {
				kdio_printf(iocom, 1, "%s\n",
					    "msgtx: state reused "
					    "for REPLY | DELETE");
				error = EINVAL;
			}
			break;
		}
		error = 0;
		break;
	case DMSGF_REPLY:
		if (msg->any.head.cmd & DMSGF_ABORT) {
			if (state == &state->iocom->state0 ||
			    (state->txcmd & DMSGF_CREATE) == 0) {
				error = EALREADY;
				break;
			}
		}
		error = 0;
		break;
	}

	/*
	 * Set interlock in case the send side blocks and a response is
	 * returned before kdmsg_state_cleanuptx() can be run.
	 */
	if (state && error == 0)
		state->flags |= KDMSG_STATE_INTERLOCK;

	return (error);
}

/*
 * Called with iocom locked.
 */
static void
kdmsg_state_cleanuptx(kdmsg_msg_t *msg)
{
	kdmsg_iocom_t *iocom = msg->state->iocom;
	kdmsg_state_t *state;

	if ((state = msg->state) == NULL) {
		kdmsg_msg_free(msg);
		return;
	}

	/*
	 * Clear interlock in case the send side blocks and a response is
	 * returned in the other thread before kdmsg_state_cleanuptx() runs.
	 */
	if (state->flags & KDMSG_STATE_SIGNAL)
		wakeup(state);
	state->flags &= ~(KDMSG_STATE_INTERLOCK | KDMSG_STATE_SIGNAL);
	kdmsg_state_hold(state);

	if (msg->any.head.cmd & DMSGF_DELETE) {
		KKASSERT((state->txcmd & DMSGF_DELETE) == 0);
		state->txcmd |= DMSGF_DELETE;
		if (state->rxcmd & DMSGF_DELETE) {
			KKASSERT(state->flags & KDMSG_STATE_RBINSERTED);
			if (state->txcmd & DMSGF_REPLY) {
				KKASSERT(msg->any.head.cmd & DMSGF_REPLY);
				RB_REMOVE(kdmsg_state_tree,
					  &iocom->staterd_tree, state);
			} else {
				KKASSERT((msg->any.head.cmd & DMSGF_REPLY) == 0);
				RB_REMOVE(kdmsg_state_tree,
					  &iocom->statewr_tree, state);
			}
			state->flags &= ~KDMSG_STATE_RBINSERTED;

			if (TAILQ_EMPTY(&state->subq))
				kdmsg_subq_delete(state);
			kdmsg_msg_free(msg);
			kdmsg_state_drop(state);   /* state on rbtree */
		} else {
			kdmsg_msg_free(msg);
		}
	} else {
		kdmsg_msg_free(msg);
	}

	/*
	 * Deferred abort after transmission.
	 */
	if ((state->flags & (KDMSG_STATE_ABORTING | KDMSG_STATE_DYING)) &&
	    (state->rxcmd & DMSGF_DELETE) == 0) {
		state->flags &= ~KDMSG_STATE_ABORTING;
		kdmsg_state_abort(state);
	}
	kdmsg_state_drop(state);
}

static void
kdmsg_state_hold(kdmsg_state_t *state)
{
	atomic_add_int(&state->refs, 1);
}

static void
kdmsg_state_drop(kdmsg_state_t *state)
{
	KKASSERT(state->refs > 0);
	if (atomic_fetchadd_int(&state->refs, -1) == 1)
		kdmsg_state_free(state);
}

static void
kdmsg_state_free(kdmsg_state_t *state)
{
	kdmsg_iocom_t *iocom = state->iocom;

	KKASSERT((state->flags & KDMSG_STATE_RBINSERTED) == 0);
	KKASSERT((state->flags & KDMSG_STATE_SUBINSERTED) == 0);
	KKASSERT(TAILQ_EMPTY(&state->subq));

	if (state != &state->iocom->state0)
		kfree(state, iocom->mmsg);
}

kdmsg_msg_t *
kdmsg_msg_alloc(kdmsg_state_t *state, uint32_t cmd,
		int (*func)(kdmsg_state_t *, kdmsg_msg_t *), void *data)
{
	kdmsg_iocom_t *iocom = state->iocom;
	kdmsg_state_t *pstate;
	kdmsg_msg_t *msg;
	size_t hbytes;

	KKASSERT(iocom != NULL);
	hbytes = (cmd & DMSGF_SIZE) * DMSG_ALIGN;
	msg = kmalloc(offsetof(struct kdmsg_msg, any) + hbytes,
		      iocom->mmsg, M_WAITOK | M_ZERO);
	msg->hdr_size = hbytes;

	if ((cmd & (DMSGF_CREATE | DMSGF_REPLY)) == DMSGF_CREATE) {
		/*
		 * New transaction, requires tracking state and a unique msgid
		 * to be allocated.
		 */
		pstate = state;
		state = kmalloc(sizeof(*state), iocom->mmsg, M_WAITOK | M_ZERO);
		TAILQ_INIT(&state->subq);
		state->iocom = iocom;
		state->parent = pstate;
		state->flags = KDMSG_STATE_DYNAMIC | KDMSG_STATE_NEW;
		state->func = func;
		state->any.any = data;
		state->msgid = (uint64_t)(uintptr_t)state;

		lockmgr(&iocom->msglk, LK_EXCLUSIVE);
		if (RB_INSERT(kdmsg_state_tree, &iocom->statewr_tree, state))
			panic("duplicate msgid allocated");
		if (TAILQ_EMPTY(&pstate->subq))
			kdmsg_state_hold(pstate);/* pstate->subq */
		TAILQ_INSERT_TAIL(&pstate->subq, state, entry);
		state->flags |= KDMSG_STATE_RBINSERTED |
				KDMSG_STATE_SUBINSERTED;
		state->flags |= pstate->flags & KDMSG_STATE_DYING;
		kdmsg_state_hold(state);	/* pstate->subq */
		kdmsg_state_hold(state);	/* state on rbtree */
		kdmsg_state_hold(state);	/* msg->state */
		lockmgr(&iocom->msglk, LK_RELEASE);
	} else {
		pstate = state->parent;
		KKASSERT(pstate != NULL);
		kdmsg_state_hold(state);	/* msg->state */
	}

	if (state->flags & KDMSG_STATE_OPPOSITE)
		cmd |= DMSGF_REVTRANS;
	if (pstate->flags & KDMSG_STATE_OPPOSITE)
		cmd |= DMSGF_REVCIRC;

	msg->any.head.magic = DMSG_HDR_MAGIC;
	msg->any.head.cmd = cmd;
	msg->any.head.msgid = state->msgid;
	msg->any.head.circuit = pstate->msgid;
	msg->state = state;

	return (msg);
}

void
kdmsg_msg_free(kdmsg_msg_t *msg)
{
	kdmsg_iocom_t *iocom = msg->state->iocom;
	kdmsg_state_t *state;

	if ((msg->flags & KDMSG_FLAG_AUXALLOC) &&
	    msg->aux_data && msg->aux_size) {
		kfree(msg->aux_data, iocom->mmsg);
		msg->aux_data = NULL;
		msg->flags &= ~KDMSG_FLAG_AUXALLOC;
	}
	if ((state = msg->state) != NULL) {
		msg->state = NULL;
		kdmsg_state_drop(state);	/* msg->state */
	}
	msg->aux_data = NULL;
	msg->aux_size = 0;

	kfree(msg, iocom->mmsg);
}

/*
 * Indexed messages are stored in a red-black tree indexed by their msgid.
 * Only persistent messages are indexed.
 */
int
kdmsg_state_cmp(kdmsg_state_t *state1, kdmsg_state_t *state2)
{
	if (state1->iocom < state2->iocom)
		return(-1);
	if (state1->iocom > state2->iocom)
		return(1);
	if (state1->msgid < state2->msgid)
		return(-1);
	if (state1->msgid > state2->msgid)
		return(1);
	return(0);
}

/*
 * Write a message.  All requisit command flags have been set.  This function
 * merely queues the message to the management thread, it does not write to
 * the message socket/pipe.
 */
void
kdmsg_msg_write(kdmsg_msg_t *msg)
{
	kdmsg_iocom_t *iocom = msg->state->iocom;

	lockmgr(&iocom->msglk, LK_EXCLUSIVE);
	kdmsg_msg_write_locked(iocom, msg);
	lockmgr(&iocom->msglk, LK_RELEASE);
}

static void
kdmsg_msg_write_locked(kdmsg_iocom_t *iocom, kdmsg_msg_t *msg)
{
	kdmsg_state_t *state;

	if (msg->state) {
		/*
		 * Continuance or termination of existing transaction.
		 */
		state = msg->state;
		msg->any.head.msgid = state->msgid;
	} else {
		/*
		 * One-off message (always uses msgid 0).
		 */
		state = NULL;
		msg->any.head.msgid = 0;
	}

	/*
	 * For stateful messages, if the circuit is dead or dying we have to
	 * abort the potentially newly-created state and discard the message.
	 */
	if (state) {
		KKASSERT((state->txcmd & DMSGF_DELETE) == 0);
		if (state->flags & KDMSG_STATE_DYING) {
			kdmsg_state_hold(state);
			kdmsg_state_msgtx(msg);
			kdmsg_state_cleanuptx(msg);
			kdmsg_state_drop(state);
			return;
		}
	}

	/*
	 * Finish up the msg fields.  hdr_crc is computed over the entire
	 * (aligned) header from offset 0 with the field zeroed -- this matches
	 * both the DragonFly kernel and userland libdmsg, so the service
	 * accepts our frames.  aux_crc covers the aligned aux data.
	 */
	msg->any.head.salt = (iocom->msg_seq & 255);
	++iocom->msg_seq;

	if (msg->aux_data && msg->aux_size) {
		uint32_t abytes = DMSG_DOALIGN(msg->aux_size);

		msg->any.head.aux_bytes = msg->aux_size;
		msg->any.head.aux_crc = iscsi_crc32(msg->aux_data, abytes);
	}
	msg->any.head.hdr_crc = 0;
	msg->any.head.hdr_crc = iscsi_crc32(msg->any.buf, msg->hdr_size);

	/*
	 * If termination races new message senders we must drain the message
	 * immediately instead of queue it.
	 */
	if (iocom->flags & KDMSG_IOCOMF_EXITNOACC)
		kdmsg_drain_msg(msg);
	else
		TAILQ_INSERT_TAIL(&iocom->msgq, msg, qentry);

	if (iocom->msg_ctl & KDMSG_CLUSTERCTL_SLEEPING) {
		atomic_clear_int(&iocom->msg_ctl, KDMSG_CLUSTERCTL_SLEEPING);
		wakeup(&iocom->msg_ctl);
	}
}

/*
 * Reply to a message and terminate our side of the transaction.
 */
void
kdmsg_msg_reply(kdmsg_msg_t *msg, uint32_t error)
{
	kdmsg_state_t *state = msg->state;
	kdmsg_msg_t *nmsg;
	uint32_t cmd;

	cmd = DMSG_LNK_ERROR;

	if (state != &state->iocom->state0) {
		if (state->txcmd & DMSGF_DELETE)
			return;
		if ((state->txcmd & DMSGF_CREATE) == 0)
			cmd |= DMSGF_CREATE;
		if (state->txcmd & DMSGF_REPLY)
			cmd |= DMSGF_REPLY;
		cmd |= DMSGF_DELETE;
	} else {
		if ((msg->any.head.cmd & DMSGF_REPLY) == 0)
			cmd |= DMSGF_REPLY;
	}

	nmsg = kdmsg_msg_alloc(state, cmd, NULL, NULL);
	nmsg->any.head.error = error;
	kdmsg_msg_write(nmsg);
}

/*
 * Reply to a message and continue our side of the transaction.
 */
void
kdmsg_msg_result(kdmsg_msg_t *msg, uint32_t error)
{
	kdmsg_state_t *state = msg->state;
	kdmsg_msg_t *nmsg;
	uint32_t cmd;

	cmd = DMSG_LNK_ERROR;

	if (state != &state->iocom->state0) {
		if (state->txcmd & DMSGF_DELETE)
			return;
		if ((state->txcmd & DMSGF_CREATE) == 0)
			cmd |= DMSGF_CREATE;
		if (state->txcmd & DMSGF_REPLY)
			cmd |= DMSGF_REPLY;
		/* continuing transaction, do not set MSGF_DELETE */
	} else {
		if ((msg->any.head.cmd & DMSGF_REPLY) == 0)
			cmd |= DMSGF_REPLY;
	}

	nmsg = kdmsg_msg_alloc(state, cmd, NULL, NULL);
	nmsg->any.head.error = error;
	kdmsg_msg_write(nmsg);
}

/*
 * Reply to a message and terminate our side of the transaction (by state).
 */
void
kdmsg_state_reply(kdmsg_state_t *state, uint32_t error)
{
	kdmsg_msg_t *nmsg;
	uint32_t cmd;

	cmd = DMSG_LNK_ERROR;

	KKASSERT(state);
	if (state->txcmd & DMSGF_DELETE)
		return;
	if ((state->txcmd & DMSGF_CREATE) == 0)
		cmd |= DMSGF_CREATE;
	if (state->txcmd & DMSGF_REPLY)
		cmd |= DMSGF_REPLY;
	cmd |= DMSGF_DELETE;

	nmsg = kdmsg_msg_alloc(state, cmd, NULL, NULL);
	nmsg->any.head.error = error;
	kdmsg_msg_write(nmsg);
}

/*
 * Reply to a message and continue our side of the transaction (by state).
 */
void
kdmsg_state_result(kdmsg_state_t *state, uint32_t error)
{
	kdmsg_msg_t *nmsg;
	uint32_t cmd;

	cmd = DMSG_LNK_ERROR;

	KKASSERT(state);
	if (state->txcmd & DMSGF_DELETE)
		return;
	if ((state->txcmd & DMSGF_CREATE) == 0)
		cmd |= DMSGF_CREATE;
	if (state->txcmd & DMSGF_REPLY)
		cmd |= DMSGF_REPLY;
	/* continuing transaction, do not set MSGF_DELETE */

	nmsg = kdmsg_msg_alloc(state, cmd, NULL, NULL);
	nmsg->any.head.error = error;
	kdmsg_msg_write(nmsg);
}

/*
 * Undefine the compat shim macros so they do not leak into hammer2_iocom.c,
 * which textually includes this file and continues with its own code.
 */
#undef lockmgr
#undef lksleep
#undef lockinit
#undef kmalloc
#undef kfree
#undef fdrop
#undef fp_shutdown
#undef lwkt_exit
#undef kdio_printf

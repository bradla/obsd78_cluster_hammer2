
#define KDMSG_CLUSTERCTL_UNUSED01	0x00000001
#define KDMSG_CLUSTERCTL_KILLRX		0x00000002 /* staged helper exit */
#define KDMSG_CLUSTERCTL_KILLTX		0x00000004 /* staged helper exit */
#define KDMSG_CLUSTERCTL_SLEEPING	0x00000008 /* interlocked w/msglk */

//static int kdmsg_msg_receive_handling(kdmsg_msg_t *msg);
//static int kdmsg_state_msgrx(kdmsg_msg_t *msg);
//static int kdmsg_state_msgtx(kdmsg_msg_t *msg);
//static void kdmsg_state_cleanuprx(kdmsg_msg_t *msg);
//static void kdmsg_state_cleanuptx(kdmsg_msg_t *msg);
//static void kdmsg_state_abort(kdmsg_state_t *state);
static void kdmsg_state_free(kdmsg_state_t *state);

static void kdmsg_iocom_thread_rd(void *arg);
static void kdmsg_iocom_thread_wr(void *arg);
static void kdmsg_msg_receive(kdmsg_iocom_t *iocom, kdmsg_msg_t *msg);
//static int kdmsg_autorxmsg(kdmsg_msg_t *msg);

/*static struct lwkt_token kdmsg_token = LWKT_TOKEN_INITIALIZER(kdmsg_token);*/

/*
 * Initialize the roll-up communications structure for a network
 * messaging session.  This function does not install the socket.
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
	//init(&iocom->msglk, 0, "h2msg", 0, LK_NOWAIT);
	TAILQ_INIT(&iocom->msgq);
	RB_INIT(&iocom->staterd_tree);
	RB_INIT(&iocom->statewr_tree);

	iocom->state0.iocom = iocom;
	iocom->state0.parent = &iocom->state0;
	TAILQ_INIT(&iocom->state0.subq);
}

/*
 * dmsg CRC helpers.
 *
 * The dmsg protocol uses the iSCSI (Castagnoli) CRC32, which is exactly
 * what the kernel's iscsi_crc32 provides and what the userland libdmsg
 * service computes -- so the two interoperate on the wire.
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

		error = soreceive(so, NULL, &uio, NULL, NULL, &flags);
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
 * Receive-side dispatch for a fully-assembled message.
 *
 * Resolve the transaction state (a reply/continuation carries the msgid of
 * a state we created, tracked on state0's subq), dispatch to the per-state
 * callback or the generic receive handler, then tear down dynamic state on
 * transaction close.
 *
 * NOTE: This is the stage-1 receiver -- it handles the LNK_CONN/LNK_SPAN
 *	 handshake and one-off messages.  The full DragonFly RX state machine
 *	 (RB msgid trees, circuit relaying, abort handling) is a later stage.
 */
static void
kdmsg_msg_receive(kdmsg_iocom_t *iocom, kdmsg_msg_t *msg)
{
	kdmsg_state_t *state = NULL;
	kdmsg_state_t *scan;
	uint32_t cmd = msg->any.head.cmd;

	TAILQ_FOREACH(scan, &iocom->state0.subq, entry) {
		if (scan->msgid == msg->any.head.msgid) {
			state = scan;
			break;
		}
	}
	if (state == NULL)
		state = &iocom->state0;
	msg->state = state;
	msg->tcmd = state->icmd ? state->icmd : (cmd & DMSGF_CMDSWMASK);

	if (state->func)
		state->func(state, msg);
	else if (iocom->rcvmsg)
		iocom->rcvmsg(msg);

	if ((cmd & DMSGF_DELETE) && state != &iocom->state0 &&
	    (state->flags & KDMSG_STATE_DYNAMIC)) {
		if (state->flags & KDMSG_STATE_INSERTED) {
			TAILQ_REMOVE(&state->parent->subq, state, entry);
			state->flags &= ~KDMSG_STATE_INSERTED;
		}
		kdmsg_state_free(state);
	}

	kdmsg_msg_free(msg);
}

/*
 * Cluster connection reader thread.
 *
 * Reads dmsg frames off the socket, validates the core header (magic +
 * hdr_crc), assembles the extended header and any auxillary data, verifies
 * the aux CRC, and dispatches the completed message via kdmsg_msg_receive().
 */
static void
kdmsg_iocom_thread_rd(void *arg)
{
	kdmsg_iocom_t *iocom = arg;
	struct socket *so;
	dmsg_hdr_t hdr;
	kdmsg_msg_t *msg;
	size_t hbytes, abytes, ext;
	uint32_t xcrc32, ncrc32;
	int error = 0;

	so = (iocom->msg_fp != NULL) ? iocom->msg_fp->f_data : NULL;

	while (so != NULL &&
	    (iocom->msg_ctl & (KDMSG_CLUSTERCTL_KILL |
			       KDMSG_CLUSTERCTL_KILLRX)) == 0) {
		/*
		 * Read the fixed core header.
		 */
		error = kdmsg_soread(so, &hdr, sizeof(hdr));
		if (error)
			break;

		if (hdr.magic != DMSG_HDR_MAGIC &&
		    hdr.magic != DMSG_HDR_MAGIC_REV) {
			hprintf("bad dmsg magic %04x\n", hdr.magic);
			error = EINVAL;
			break;
		}
		/*
		 * NOTE: byte-swapped links (DMSG_HDR_MAGIC_REV) are not yet
		 *	 supported; both endpoints are the same endian.
		 */
		hbytes = (hdr.cmd & DMSGF_SIZE) * DMSG_ALIGN;
		if (hbytes < sizeof(hdr) || hbytes > DMSG_HDR_MAX) {
			hprintf("bad dmsg hdr size %zu\n", hbytes);
			error = EINVAL;
			break;
		}
		abytes = hdr.aux_bytes;
		if (abytes > DMSG_AUX_MAX) {
			hprintf("bad dmsg aux size %zu\n", abytes);
			error = EINVAL;
			break;
		}

		/*
		 * Allocate the message sized for the (possibly extended)
		 * header.  Strip CREATE/REPLY so msg_alloc does not allocate
		 * transmit state; the real header (and state) are resolved
		 * below / in kdmsg_msg_receive().
		 */
		msg = kdmsg_msg_alloc(&iocom->state0,
				      hdr.cmd & ~(DMSGF_CREATE | DMSGF_REPLY),
				      NULL, NULL);
		msg->any.head = hdr;

		/*
		 * Read the extended header, if any.
		 */
		ext = hbytes - sizeof(hdr);
		if (ext > 0) {
			error = kdmsg_soread(so,
			    (char *)&msg->any.head + sizeof(hdr), ext);
			if (error) {
				kdmsg_msg_free(msg);
				break;
			}
		}

		/*
		 * Verify header CRC (computed over the aligned header with
		 * the hdr_crc field zeroed).
		 */
		xcrc32 = msg->any.head.hdr_crc;
		msg->any.head.hdr_crc = 0;
		ncrc32 = kdmsg_icrc32((char *)&msg->any.head + DMSG_HDR_CRCOFF,
				      hbytes - DMSG_HDR_CRCOFF);
		msg->any.head.hdr_crc = xcrc32;
		if (ncrc32 != xcrc32) {
			hprintf("dmsg hdr crc mismatch %08x != %08x\n",
				ncrc32, xcrc32);
			kdmsg_msg_free(msg);
			error = EINVAL;
			break;
		}

		/*
		 * Read auxillary data (transmitted padded to DMSG_ALIGN);
		 * store the unaligned length and verify the aux CRC.
		 */
		if (abytes > 0) {
			size_t apad = DMSG_DOALIGN(abytes);

			msg->aux_data = malloc(apad, (size_t)iocom->mmsg,
					       M_WAITOK | M_ZERO);
			msg->aux_size = abytes;
			msg->flags |= KDMSG_FLAG_AUXALLOC;
			error = kdmsg_soread(so, msg->aux_data, apad);
			if (error) {
				kdmsg_msg_free(msg);
				break;
			}
			xcrc32 = kdmsg_icrc32(msg->aux_data, apad);
			if (xcrc32 != hdr.aux_crc) {
				hprintf("dmsg aux crc mismatch\n");
				kdmsg_msg_free(msg);
				error = EINVAL;
				break;
			}
		}

		kdmsg_msg_receive(iocom, msg);
	}

	if (error)
		hprintf("reader thread exiting, error %d\n", error);

	atomic_setbits_int(&iocom->msg_ctl, KDMSG_CLUSTERCTL_KILL);
	iocom->msgrd_td = NULL;
	wakeup(&iocom->msg_ctl);
	wakeup(iocom);
	kthread_exit(0);
}

/*
 * Cluster connection writer thread.
 *
 * Drains iocom->msgq, finalizes CRCs, serializes each message (header then
 * aligned auxillary data), and writes it to the socket.
 */
static void
kdmsg_iocom_thread_wr(void *arg)
{
	kdmsg_iocom_t *iocom = arg;
	struct socket *so;
	kdmsg_msg_t *msg;
	int error = 0;

	so = (iocom->msg_fp != NULL) ? iocom->msg_fp->f_data : NULL;

	while (so != NULL &&
	    (iocom->msg_ctl & (KDMSG_CLUSTERCTL_KILL |
			       KDMSG_CLUSTERCTL_KILLTX)) == 0) {
		msg = TAILQ_FIRST(&iocom->msgq);
		if (msg == NULL) {
			atomic_setbits_int(&iocom->msg_ctl,
					   KDMSG_CLUSTERCTL_SLEEPING);
			tsleep(&iocom->msg_ctl, PWAIT, "kdmwr", hz);
			atomic_clearbits_int(&iocom->msg_ctl,
					     KDMSG_CLUSTERCTL_SLEEPING);
			continue;
		}
		TAILQ_REMOVE(&iocom->msgq, msg, qentry);

		/*
		 * Finalize CRCs: aux_crc over the aligned aux data, hdr_crc
		 * over the aligned header with the field zeroed.
		 */
		if (msg->aux_data && msg->aux_size) {
			size_t apad = DMSG_DOALIGN(msg->aux_size);

			msg->any.head.aux_bytes = msg->aux_size;
			msg->any.head.aux_crc =
			    kdmsg_icrc32(msg->aux_data, apad);
		}
		msg->any.head.hdr_crc = 0;
		msg->any.head.hdr_crc =
		    kdmsg_icrc32((char *)&msg->any.head + DMSG_HDR_CRCOFF,
				 msg->hdr_size - DMSG_HDR_CRCOFF);

		error = kdmsg_sowrite(so, &msg->any.head, msg->hdr_size);
		if (error == 0 && msg->aux_data && msg->aux_size) {
			error = kdmsg_sowrite(so, msg->aux_data,
					      DMSG_DOALIGN(msg->aux_size));
		}
		kdmsg_msg_free(msg);
		if (error)
			break;
	}

	if (error)
		hprintf("writer thread exiting, error %d\n", error);

	atomic_setbits_int(&iocom->msg_ctl, KDMSG_CLUSTERCTL_KILL);
	atomic_setbits_int(&iocom->flags, KDMSG_IOCOMF_EXITNOACC);
	iocom->msgwr_td = NULL;
	wakeup(&iocom->msg_ctl);
	wakeup(iocom);
	kthread_exit(0);
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
	//lockmgr(&iocom->msglk, LK_EXCLUSIVE, NULL);
	atomic_setbits_int(&iocom->msg_ctl, KDMSG_CLUSTERCTL_KILL);
	while (iocom->msgrd_td || iocom->msgwr_td) {
		wakeup(&iocom->msg_ctl);
		tsleep(iocom, PWAIT, "clstrkl", hz);
	}

	/*
	 * Drop communications descriptor
	 */
	if (iocom->msg_fp) {
		FRELE(iocom->msg_fp, curproc);	/* OpenBSD: drop fd_getfile ref */
		iocom->msg_fp = NULL;
	}

	/*
	 * Setup new communications descriptor
	 */
	iocom->msg_ctl = 0;
	iocom->msg_fp = fp;
	iocom->msg_seq = 0;
	iocom->flags &= ~KDMSG_IOCOMF_EXITNOACC;

	/*
	 * Spawn the read/write service threads.  Each clears its td pointer
	 * and wakes &iocom->msg_ctl on exit; the teardown loop above waits
	 * on that.
	 */
	kthread_create(kdmsg_iocom_thread_rd, iocom, &iocom->msgrd_td,
		       subsysname);
	kthread_create(kdmsg_iocom_thread_wr, iocom, &iocom->msgwr_td,
		       subsysname);
}

/*
 * Caller sets up iocom->auto_lnk_conn and iocom->auto_lnk_span, then calls
 * this function to handle the state machine for LNK_CONN and LNK_SPAN.
 */
static int kdmsg_lnk_conn_reply(kdmsg_state_t *state, kdmsg_msg_t *msg);
static int kdmsg_lnk_span_reply(kdmsg_state_t *state, kdmsg_msg_t *msg);

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
	kdmsg_msg_write(msg);
}

static
int
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
	 * transaction is deleted.  For deletions this gives device drivers
	 * the ability to interlock new operations on the circuit before
	 * it becomes illegal and panics.
	 */
	if (iocom->auto_callback)
		iocom->auto_callback(msg);

	if ((state->txcmd & DMSGF_DELETE) == 0 &&
	    (msg->any.head.cmd & DMSGF_DELETE)) {
		iocom->conn_state = NULL;
		kdmsg_msg_reply(msg, 0);
	}

	return (0);
}

static
int
kdmsg_lnk_span_reply(kdmsg_state_t *state, kdmsg_msg_t *msg)
{
	/*
	 * Be sure to process shim before terminating the SPAN
	 * transaction.  Gives device drivers the ability to
	 * interlock new operations on the circuit before it
	 * becomes illegal and panics.
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

	/*
	 * Ask the cluster controller to go away
	 */
	//lockmgr(&iocom->msglk, LK_EXCLUSIVE, 0);
	atomic_setbits_int(&iocom->msg_ctl, KDMSG_CLUSTERCTL_KILL);

	while (iocom->msgrd_td || iocom->msgwr_td) {
		wakeup(&iocom->msg_ctl);
		tsleep(iocom, (long)&iocom->msglk, 0, hz);
	}

	/*
	 * Cleanup caches
	 */
	if ((state = iocom->freerd_state) != NULL) {
		iocom->freerd_state = NULL;
		kdmsg_state_free(state);
	}

	if ((state = iocom->freewr_state) != NULL) {
		iocom->freewr_state = NULL;
		kdmsg_state_free(state);
	}

	/*
	 * Drop communications descriptor
	 */
	if (iocom->msg_fp) {
		FRELE(iocom->msg_fp, curproc);	/* OpenBSD: drop fd_getfile ref */
		iocom->msg_fp = NULL;
	}
	//lockmgr(&iocom->msglk, LK_RELEASE, 0);
}


/*
 * This cleans out the pending transmit message queue, adjusting any
 * persistent states properly in the process.
 *
 * Caller must hold pmp->iocom.msglk
 */
 /*
void
kdmsg_drain_msgq(kdmsg_iocom_t *iocom)
{
	kdmsg_msg_t *msg;


	while ((msg = TAILQ_FIRST(&iocom->msgq)) != NULL) {
		TAILQ_REMOVE(&iocom->msgq, msg, qentry);

		if (kdmsg_state_msgtx(msg))
			kdmsg_msg_free(msg);
		else
			kdmsg_state_cleanuptx(msg);
	}
}
*/



static
void
kdmsg_state_free(kdmsg_state_t *state)
{
	kdmsg_iocom_t *iocom = state->iocom;

	// XX KKASSERT((state->flags & KDMSG_STATE_INSERTED) == 0);
	free(state, (long long)iocom->mmsg, 0);
}

kdmsg_msg_t *
kdmsg_msg_alloc(kdmsg_state_t *state, uint32_t cmd,
		int (*func)(kdmsg_state_t *, kdmsg_msg_t *), void *data)
{
	kdmsg_iocom_t *iocom = state->iocom;
	kdmsg_state_t *pstate;
	kdmsg_msg_t *msg;
	size_t hbytes;

	// XX KKASSERT(iocom != NULL);
	hbytes = (cmd & DMSGF_SIZE) * DMSG_ALIGN;
	msg = malloc(offsetof(struct kdmsg_msg, any) + hbytes,
		      (size_t)iocom->mmsg, M_WAITOK | M_ZERO);
	msg->hdr_size = hbytes;

	if ((cmd & (DMSGF_CREATE | DMSGF_REPLY)) == DMSGF_CREATE) {
		/*
		 * New transaction, requires tracking state and a unique
		 * msgid to be allocated.
		 */
		pstate = state;
		state = malloc(sizeof(*state), (size_t)iocom->mmsg, M_WAITOK | M_ZERO);
		TAILQ_INIT(&state->subq);
		state->iocom = iocom;
		state->parent = pstate;
		state->flags = KDMSG_STATE_DYNAMIC;
		state->func = func;
		state->any.any = data;
		state->msgid = (uint64_t)(uintptr_t)state;
		/*msg->any.head.msgid = state->msgid;XXX*/

		//lockmgr(&iocom->msglk, LK_EXCLUSIVE, NULL);
		//if (RB_INSERT(kdmsg_state_tree, &iocom->statewr_tree, state)) xxx 
			//panic("duplicate msgid allocated");
		TAILQ_INSERT_TAIL(&pstate->subq, state, entry);
		state->flags |= KDMSG_STATE_INSERTED;
		//lockmgr(&iocom->msglk, LK_RELEASE, NULL);
	} else {
		pstate = state->parent;
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

	if ((msg->flags & KDMSG_FLAG_AUXALLOC) &&
	    msg->aux_data && msg->aux_size) {
		free(msg->aux_data, (long long)iocom->mmsg, 0);
		msg->flags &= ~KDMSG_FLAG_AUXALLOC;
	}
	msg->state = NULL;
	msg->aux_data = NULL;
	msg->aux_size = 0;

	free(msg, (long long)iocom->mmsg, 0);
}

/*
 * Indexed messages are stored in a red-black tree indexed by their
 * msgid.  Only persistent messages are indexed.
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
 * Write a message.  All requisit command flags have been set.
 *
 * If msg->state is non-NULL the message is written to the existing
 * transaction.  msgid will be set accordingly.
 *
 * If msg->state is NULL and CREATE is set new state is allocated and
 * (func, data) is installed.  A msgid is assigned.
 *
 * If msg->state is NULL and CREATE is not set the message is assumed
 * to be a one-way message.  The originator must assign the msgid
 * (or leave it 0, which is typical.
 *
 * This function merely queues the message to the management thread, it
 * does not write to the message socket/pipe.
 */
void
kdmsg_msg_write(kdmsg_msg_t *msg)
{
	kdmsg_iocom_t *iocom = msg->state->iocom;
	kdmsg_state_t *state;

	if (msg->state) {
		/*
		 * Continuance or termination of existing transaction.
		 * The transaction could have been initiated by either end.
		 *
		 * (Function callback and aux data for the receive side can
		 * be replaced or left alone).
		 */
		state = msg->state;
		msg->any.head.msgid = state->msgid;
		//lockmgr(&iocom->msglk, LK_EXCLUSIVE, NULL);
	} else {
		/*
		 * One-off message (always uses msgid 0 to distinguish
		 * between a possibly lost in-transaction message due to
		 * competing aborts and a real one-off message?)
		 */
		state = NULL;
		msg->any.head.msgid = 0;
		//lockmgr(&iocom->msglk, LK_EXCLUSIVE, NULL);
	}

	/*
	 * This flag is not set until after the tx thread has drained
	 * the txmsgq and simulated responses.  After that point the
	 * txthread is dead and can no longer simulate responses.
	 *
	 * Device drivers should never try to send a message once this
	 * flag is set.  They should have detected (through the state
	 * closures) that the link is in trouble.
	 */
	if (iocom->flags & KDMSG_IOCOMF_EXITNOACC) {
		//lockmgr(&iocom->msglk, LK_RELEASE, NULL);
		panic("kdmsg_msg_write: Attempt to write message to "
		      "terminated iocom\n");
	}

	/*
	 * Finish up the msg fields.  Note that msg->aux_size and the
	 * aux_bytes stored in the message header represent the unaligned
	 * (actual) bytes of data, but the buffer is sized to an aligned
	 * size and the CRC is generated over the aligned length.
	 */
	msg->any.head.salt = /* (random << 8) | */ (iocom->msg_seq & 255);
	++iocom->msg_seq;

	if (msg->aux_data && msg->aux_size) {
		// XX uint32_t abytes = DMSG_DOALIGN(msg->aux_size);

		msg->any.head.aux_bytes = msg->aux_size;
		// XX fix me msg->any.head.aux_crc = iscsi_crc32(msg->aux_data, abytes);
	}
	msg->any.head.hdr_crc = 0;
	// XX fix me  msg->any.head.hdr_crc = iscsi_crc32(msg->any.buf, msg->hdr_size);

	TAILQ_INSERT_TAIL(&iocom->msgq, msg, qentry);

	if (iocom->msg_ctl & KDMSG_CLUSTERCTL_SLEEPING) {
		atomic_clear_int(&iocom->msg_ctl,
				 KDMSG_CLUSTERCTL_SLEEPING);
		wakeup(&iocom->msg_ctl);
	}

	//lockmgr(&iocom->msglk, LK_RELEASE, NULL);
}

/*
 * Reply to a message and terminate our side of the transaction.
 *
 * If msg->state is non-NULL we are replying to a one-way message.
 */
void
kdmsg_msg_reply(kdmsg_msg_t *msg, uint32_t error)
{
	kdmsg_state_t *state = msg->state;
	kdmsg_msg_t *nmsg;
	uint32_t cmd;

	/*
	 * Reply with a simple error code and terminate the transaction.
	 */
	cmd = DMSG_LNK_ERROR;

	/*
	 * Check if our direction has even been initiated yet, set CREATE.
	 *
	 * Check what direction this is (command or reply direction).  Note
	 * that txcmd might not have been initiated yet.
	 *
	 * If our direction has already been closed we just return without
	 * doing anything.
	 */
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
 *
 * If msg->state is non-NULL we are replying to a one-way message and this
 * function degenerates into the same as kdmsg_msg_reply().
 */
void
kdmsg_msg_result(kdmsg_msg_t *msg, uint32_t error)
{
	kdmsg_state_t *state = msg->state;
	kdmsg_msg_t *nmsg;
	uint32_t cmd;

	/*
	 * Return a simple result code, do NOT terminate the transaction.
	 */
	cmd = DMSG_LNK_ERROR;

	/*
	 * Check if our direction has even been initiated yet, set CREATE.
	 *
	 * Check what direction this is (command or reply direction).  Note
	 * that txcmd might not have been initiated yet.
	 *
	 * If our direction has already been closed we just return without
	 * doing anything.
	 */
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
 * Reply to a message and terminate our side of the transaction.
 *
 * If msg->state is non-NULL we are replying to a one-way message.
 */
void
kdmsg_state_reply(kdmsg_state_t *state, uint32_t error)
{
	kdmsg_msg_t *nmsg;
	uint32_t cmd;

	/*
	 * Reply with a simple error code and terminate the transaction.
	 */
	cmd = DMSG_LNK_ERROR;

	/*
	 * Check if our direction has even been initiated yet, set CREATE.
	 *
	 * Check what direction this is (command or reply direction).  Note
	 * that txcmd might not have been initiated yet.
	 *
	 * If our direction has already been closed we just return without
	 * doing anything.
	 */
	// XX KKASSERT(state);
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
 * Reply to a message and continue our side of the transaction.
 *
 * If msg->state is non-NULL we are replying to a one-way message and this
 * function degenerates into the same as kdmsg_msg_reply().
 */
void
kdmsg_state_result(kdmsg_state_t *state, uint32_t error)
{
	kdmsg_msg_t *nmsg;
	uint32_t cmd;

	/*
	 * Return a simple result code, do NOT terminate the transaction.
	 */
	cmd = DMSG_LNK_ERROR;

	/*
	 * Check if our direction has even been initiated yet, set CREATE.
	 *
	 * Check what direction this is (command or reply direction).  Note
	 * that txcmd might not have been initiated yet.
	 *
	 * If our direction has already been closed we just return without
	 * doing anything.
	 */
	// XX KKASSERT(state);
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
 * Initialize the roll-up communications structure for a network
 * messaging session.  This function does not install the socket.
 
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
	TAILQ_INIT(&iocom->state0.subq);
} */
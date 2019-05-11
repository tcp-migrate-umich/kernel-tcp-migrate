/*
 * Seamless TCP connection migration for CRIU 
 *
 * tcp_migrate is specifically designed for checkpooint restore in
 * userspace (CRIU) case where
 *    Servers: A        B
 *              \     /
 *     Client:     C
 * computation heavy workload is offloaded to server A originally and
 * process/container migrates to server B that has a new public IP
 * address. With existing solution, front-end application at client C
 * must either run a proxy or manually redirect to forward traffic to
 * new server B. 
 *
 * With tcp_migrate, server B initiates migration stage and sends
 * **tcp_migrate_req** to client C so that following traffic is
 * properly forwarded to server B.
 *
 * The original TCP migration idea is inspired from 
 *    http://nms.lcs.mit.edu/papers/e2emobility.pdf
 */
#include <net/tcp.h>

#include <linux/inet.h>
#include <linux/stddef.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/inetdevice.h>
#include <linux/sched.h>

#if !IS_ENABLED(CONFIG_TCP_MIGRATE)
int tcp_v4_migrate_hash(struct sock *sk){ return 0; }
int tcp_v4_migrate_unhash(struct sock *sk){ return 0; }
int tcp_v4_migrate_hash_place(struct sock *sk, u32 token){ return 0; }
bool tcp_v4_migrate_unhashed(const struct sock *sk){ return 0; }
#else

/* returns a new available token number (or TCP_MIGRATE_NOTOKEN if
 * they are all taken). Also advances next_token to the next open
 * slot.
 */
static u32 next_avail_token(void) 
{
	u32 curr;
	u32 start;

	get_random_bytes(&start, sizeof(start));
	start = start % MAX_TOKEN;
	curr = start;

	while (migrate_socks[curr] != NULL) {
		curr = (curr + 1) % MAX_TOKEN;
		if (curr == start) {
			// all slots are full
			return TCP_MIGRATE_NOTOKEN;
		}
	}
	return curr;
}

bool tcp_v4_migrate_unhashed(const struct sock *sk) 
{
	int i;
	for (i = 0; i < MAX_TOKEN; i++) {
		if (migrate_socks[i] == sk)
			return false;
	}
	return true;
}

/* places sk into the migrate array at index token */
int tcp_v4_migrate_hash_place(struct sock *sk, u32 token) 
{
	tcpmig_debug("[%s] migrate_hash_place: token=%u\n", __func__,
			token);

	WARN_ON(!tcp_v4_migrate_unhashed(sk));

	if (token >= MAX_TOKEN)
		return -1;

	if (migrate_socks[token] != NULL) {
		tcpmig_debug("[%s] migrate_socks[%u] already taken by %p\n",
				__func__, token, (void*)migrate_socks[token]);
		return -1;
	}
	migrate_socks[token] = sk;

	WARN_ON(tcp_sk(sk)->migrate_token != token);
	return 0;
}

/* hashes the socket into the migrate_socks array and assigns
 * the socket a migrate token
 */
int tcp_v4_migrate_hash(struct sock *sk) 
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 token = next_avail_token();
  pid_t pid = task_pid_nr(current);

	tcpmig_debug("[%s] pid=%d\n", __func__, pid);

	if (token == TCP_MIGRATE_NOTOKEN) {
    tcpmig_debug("[%s] no more tokens available pid%d\n", __func__,
        pid);
		return -1;
	}

  tcpmig_debug("[%s] assigning token to socket: %u pid=%d\n",
      __func__, token, pid);
	tp->migrate_token = token;

	if (tcp_v4_migrate_hash_place(sk, token)) {
		tp->migrate_token = TCP_MIGRATE_NOTOKEN;
		return -1;
	}

	return 0;
}

int tcp_v4_migrate_unhash(struct sock *sk) 
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 token = tp->migrate_token;
  pid_t pid = task_pid_nr(current);

	/* for pid to app name trick */
	/* FIXME-JOSEPH: may cause a kernel panic (not tested yet) */
	char appname[TASK_COMM_LEN];
	memset(appname, 0, TASK_COMM_LEN);
	get_task_comm(appname, current);

	tcpmig_debug("[%s] pid=%d, token=%u, app=%s\n", __func__, pid,
			token, appname);

	WARN_ON(tcp_v4_migrate_unhashed(sk));

	if (token >= MAX_TOKEN)
		return -1;

	if (migrate_socks[token] != sk) {
    tcpmig_debug("[%s] migrate_socks[%u] != this sk (actually %p)\n",
        __func__, token, (void*)migrate_socks[token]);
		return -1;
	}

	migrate_socks[token] = NULL;

	tp->migrate_token = TCP_MIGRATE_NOTOKEN;

	return 0;
}
#endif /* for hashing */

/* Atomically unhashes the sock from the ehash, updates its
 * destination address, and hashes it back into the ehash
 */
int tcp_v4_change_daddr(struct sock *sk, __be32 newdaddr) 
{
	int err;
	//local_bh_disable();

	printk(KERN_INFO "[%p][%s] unhashing\n", (void*)sk, __func__);
	inet_unhash(sk);

	sk->sk_daddr = newdaddr;

	printk(KERN_INFO "[%p][%s] rehashing\n", (void*)sk, __func__);
	err = inet_hash(sk);
	if (err)
		goto err;

	//local_bh_enable();
	return 0;
err:
	return err;
}

struct sock *tcp_v4_migrate_lookup(u32 token) 
{
	if (token >= MAX_TOKEN) {
		return NULL;
	}
	return migrate_socks[token];
}

int tcp_v4_migrate_request(struct sk_buff *skb, struct tcp_options_received *opts) 
{
#if !IS_ENABLED(CONFIG_TCP_MIGRATE)
  return 0; 
#else
	struct sock *sk;
	const struct iphdr *iph;
	__be32 remote_addr;
	u32 token = opts->migrate_token;
	int err;

	printk(KERN_INFO "[%s] token received is %u\n", __func__, token);

	iph = ip_hdr(skb);
	printk(KERN_INFO "[%s] iph = %p\n", __func__, iph);

	// Migrate connection to this address:
	remote_addr = iph->saddr;
	printk(KERN_INFO "[%s] remote addr is: %x\n", __func__, ntohl(remote_addr));

	/* Find the sock with this token */
	sk = tcp_v4_migrate_lookup(token);

	if (!sk) {
		printk(KERN_INFO "[%s] could not find socket with token %u\n", __func__, token);
		return -1;
	}

	printk(KERN_INFO "[%p][%s] Found sock and setting its daddr\n", (void*)sk, __func__);
	err = tcp_v4_change_daddr(sk, remote_addr);

	return err;
#endif
}
EXPORT_SYMBOL(tcp_v4_migrate_request);

/* This routine sends an ack and also updates the window. */
void tcp_send_migrate_req(struct sock *sk)
{
#if !IS_ENABLED(CONFIG_TCP_MIGRATE)
  return;
#else
	struct tcp_sock *tp = tcp_sk(sk);

	if (!tp->migrate_enabled) {
		printk(KERN_INFO "[%p][%s] migration is not enabled in this socket?\n", (void*)sk, __func__);
		return;
  	}

	if (tp->migrate_req_snd) {
		printk(KERN_INFO "[%p][%s] migrate_req_snd already set?\n", (void*)sk, __func__);
		return;
	}

	WARN_ON(tcp_v4_migrate_unhashed(sk));

	printk(KERN_INFO "[%p][%s] sending migrate request\n", (void*)sk, __func__);

	// Enable this so that tcp_established_options
	// knows to add the MIGRATE_REQ option.
	tp->migrate_req_snd = true;

	__tcp_send_ack(sk, tp->rcv_nxt);
#endif
}
EXPORT_SYMBOL_GPL(tcp_send_migrate_req);


#ifdef CONFIG_PROC_FS
static void get_tcp_mig_send_sock(struct sock *sk, struct seq_file *f, int i)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_sock *inet = inet_sk(sk);
	__be32 dest = inet->inet_daddr;
	__be32 src = inet->inet_rcv_saddr;
	__u16 destp = ntohs(inet->inet_dport);
	__u16 srcp = ntohs(inet->inet_sport);
	int state;
	bool migrate_enabled = tp->migrate_enabled;
	u32 migrate_token;

	if (!migrate_enabled)
		goto skip;

	tcp_send_migrate_req(sk);

	state = inet_sk_state_load(sk);
	migrate_token = tp->migrate_token;

	seq_printf(f, "%4d: %08X:%04X %08X:%04X %02X %d",
		i, src, srcp, dest, destp, state, migrate_token
		);
	seq_pad(f, '\n');

	// JOSEPH
	/* TODO: given tcp_mig socket, now put the socket into MIG_SYN state
	 */
skip:
	return;
}

static int tcp_mig_send_show(struct seq_file *seq, void *v) 
{
	struct tcp_iter_state *st;
	struct sock *sk = v;

	seq_setwidth(seq, 150 - 1);
	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, "  sl  local_address rem_address			token\n");
		goto out;
	}
	st = seq->private;

	if (sk->sk_state != TCP_TIME_WAIT && sk->sk_state != TCP_NEW_SYN_RECV) {
		get_tcp_mig_send_sock(v, seq, st->num);
	}

out:
	return 0;
}

static void get_tcp_mig_check_sock(struct sock *sk, struct seq_file *f, int i)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	bool migrate_enabled = tp->migrate_enabled;
	bool awaiting_ack = tp->migrate_req_snd;

	if (!migrate_enabled)
		goto skip;

	seq_printf(f, "%i", awaiting_ack);
	seq_pad(f, '\n');
skip:
	return;
}

static int tcp_mig_check_show(struct seq_file *seq, void *v) 
{
	struct tcp_iter_state *st;
	struct sock *sk = v;

	seq_setwidth(seq, 1);
	if (v == SEQ_START_TOKEN) {
		goto out;
	}
	st = seq->private;

	if (sk->sk_state != TCP_TIME_WAIT && sk->sk_state != TCP_NEW_SYN_RECV) {
		get_tcp_mig_check_sock(v, seq, st->num);
	}

out:
	return 0;
}


static const struct seq_operations tcp_mig_send_seq_ops = {
	.show		= tcp_mig_send_show,
	.start		= tcp_seq_start,
	.next		= tcp_seq_next,
	.stop		= tcp_seq_stop,
};
static const struct seq_operations tcp_mig_check_seq_ops = {
	.show		= tcp_mig_check_show,
	.start		= tcp_seq_start,
	.next		= tcp_seq_next,
	.stop		= tcp_seq_stop,
};


static struct tcp_seq_afinfo tcpmig_seq_afinfo = {
	.family		= AF_INET,
};

static int __net_init tcpmig_proc_init_net(struct net *net)
{
#if IS_ENABLED(CONFIG_TCP_MIGRATE)
	if (!proc_create_net_data("tcp_mig_req_send", 0444, net->proc_net, &tcp_mig_send_seq_ops,
			sizeof(struct tcp_iter_state), &tcpmig_seq_afinfo))
		return -ENOMEM;
	if (!proc_create_net_data("tcp_mig_req_check", 0444, net->proc_net, &tcp_mig_check_seq_ops,
			sizeof(struct tcp_iter_state), &tcpmig_seq_afinfo))
		return -ENOMEM;
#endif
	return 0;
}

static void __net_exit tcpmig_proc_exit_net(struct net *net)
{
#if IS_ENABLED(CONFIG_TCP_MIGRATE)
	remove_proc_entry("tcp_mig_req_send", net->proc_net);
	remove_proc_entry("tcp_mig_req_check", net->proc_net);
#endif
}

static struct pernet_operations tcpmig_net_ops = {
	.init = tcpmig_proc_init_net,
	.exit = tcpmig_proc_exit_net,
};

int __init tcpmig_proc_init(void)
{
	return register_pernet_subsys(&tcpmig_net_ops);
}

void tcpmig_proc_exit(void)
{
	unregister_pernet_subsys(&tcpmig_net_ops);
}
#endif /* CONFIG_PROC_FS */


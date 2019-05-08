#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/if.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <net/ip.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/file.h>
#include <linux/un.h>
#include <linux/syscalls.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lu Qiuwen");
MODULE_DESCRIPTION("Tango Frontend Engine - Tcp Restore Kernel Helper");
MODULE_VERSION("0.99");

#ifdef PATH_MAX
#define TFE_STRING_SIZE PATH_MAX
#else
#define TFE_STRING_SIZE 2048
#endif

struct nf_hook_ops nf_hook_ops_in;
static char * if_dev_name = "ens33";
static struct socket * g_scm_socket;
static struct net * local_net_ptr = &init_net;

#define TFE_KMOD_DEFAULT_CTRLMSG_SOCK_PATH "/var/run/.tfe_kmod_unsocket_ctrlmsg"
char str_ctrlmsg_sock_path[TFE_STRING_SIZE] = TFE_KMOD_DEFAULT_CTRLMSG_SOCK_PATH;

module_param(if_dev_name, charp, 0660);

struct tcp_restore_info_endpoint
{
	struct sockaddr_storage addr;
	bool wscale_perm;
	bool timestamp_perm;
	bool sack_perm;
	uint16_t mss;
};

struct tcp_restore_info_global
{
	uint32_t seq;
	uint32_t ack;
};

struct tcp_restore_info
{
	struct tcp_restore_info_global global;
	struct tcp_restore_info_endpoint client;
	struct tcp_restore_info_endpoint server;
};


enum tcp_restore_info_tlv_type
{
	TCP_RESTORE_INFO_TLV_SEQ,
	TCP_RESTORE_INFO_TLV_ACK,
	TCP_RESTORE_INFO_TLV_MSS_CLIENT,
	TCP_RESTORE_INFO_TLV_MSS_SERVER,
	TCP_RESTORE_INFO_TLV_WSACLE_CLIENT,
	TCP_RESTORE_INFO_TLV_WSACLE_SERVER,
	TCP_RESTORE_INFO_TLV_SACK_CLIENT,
	TCP_RESTORE_INFO_TLV_SACK_SERVER,
	TCP_RESTORE_INFO_TLV_TS_CLIENT,
	TCP_RESTORE_INFO_TLV_TS_SERVER,
	TCP_RESTORE_INFO_TLV_USER_DEFINED
};

struct tcp_restore_info_tlv
{
	uint16_t type;
	uint16_t length;
	
	union
	{
		uint8_t value_as_uint8[0];
		uint16_t value_as_uint16[0];
		uint32_t value_as_uint32[0];
		unsigned char value_as_string[0];
	};

} __attribute__((packed));

struct tcp_restore_info_header
{
	uint8_t __magic__[2]; /* Must be 0x4d, 0x5a */
	uint16_t nr_tlvs;
	struct tcp_restore_info_tlv tlvs[0];
} __attribute__((packed));

static void __tcp_restore_info_parse_from_skb(struct sk_buff * skb, struct tcp_restore_info * out)
{
	struct iphdr * iphdr = ip_hdr(skb);
	struct tcphdr * tcphdr = tcp_hdr(skb);

	struct sockaddr_in * in_addr_client = (struct sockaddr_in *)&out->client.addr;
	struct sockaddr_in * in_addr_server = (struct sockaddr_in *)&out->server.addr;

	in_addr_client->sin_family = AF_INET;
	in_addr_client->sin_addr.s_addr = iphdr->saddr;
	in_addr_client->sin_port = tcphdr->source;

	in_addr_server->sin_family = AF_INET;
	in_addr_server->sin_addr.s_addr = iphdr->daddr;
	in_addr_client->sin_port = tcphdr->dest;

	return;
}

static int __tcp_restore_info_parse_from_clienthello(const char * data, unsigned int datalen, struct tcp_restore_info * out)
{
	/* For temporary test */
	uint32_t __seq = *(const uint32_t *)(data + 0 * sizeof(uint32_t));
	uint32_t __ack = *(const uint32_t *)(data + 1 * sizeof(uint32_t));

	out->global.seq = __seq;
	out->global.ack = __ack;

	printk(KERN_DEBUG "Hit clienthello, seq = %u, ack = %u\n", out->global.seq, out->global.ack);
	return 0;
} 

static int __fd_send_to_tfe_userspace(struct socket * un_sock, 
		int fd_client, int fd_server, const uint8_t * msg, unsigned int msglen)
{
	union
	{
		char   buf[CMSG_SPACE(sizeof(int) * 2)];
		struct cmsghdr align;
	} controlMsg;

	struct cmsghdr *cmsgp;
	struct msghdr msgh;
	int result;

	struct kvec iv;
	iv.iov_base = (void *)msg;
	iv.iov_len = msglen;

	memset(&msgh, 0, sizeof(msgh));
	iov_iter_kvec(&msgh.msg_iter, ITER_KVEC | WRITE, &iv, 1, msglen);

	msgh.msg_name = NULL;
	msgh.msg_namelen = 0;
	msgh.msg_control = controlMsg.buf;
	msgh.msg_controllen = sizeof(controlMsg.buf);
	
	memset(controlMsg.buf, 0, sizeof(controlMsg.buf));
	cmsgp = CMSG_FIRSTHDR(&msgh);
	cmsgp->cmsg_len = CMSG_LEN(sizeof(int) * 2);
	cmsgp->cmsg_level = SOL_SOCKET;
	cmsgp->cmsg_type = SCM_RIGHTS;

	((int *) CMSG_DATA(cmsgp))[0] = fd_client;
	((int *) CMSG_DATA(cmsgp))[1] = fd_server;

	result = un_sock->ops->sendmsg(un_sock, &msgh, msglen);
	if(unlikely(result < 0))
	{
		printk(KERN_ERR "Failed at sendmsg to scm unix domain socket, result = %d\n", result);
		goto errout;
	}

	return 0;

errout:
	return -1;
}

static int __tcp_restore_fd_create(const struct tcp_restore_info_endpoint * endpoint, 
		const struct tcp_restore_info_endpoint * peer)
{
	struct socket * __sock;
	struct file * __file;
	int __fd;

	int result;
	int sockopt;

	result = sock_create_kern(local_net_ptr, AF_INET, SOCK_STREAM, IPPROTO_TCP, &__sock);
	if (result < 0)
	{
		printk(KERN_ERR "Failed at creating client's socket at kern\n");
		goto errout;
	}

	sockopt = 1;

	/* Setup TCP REPAIR Status */
	result = sock_setsockopt(__sock, SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));
	if (result < 0)
	{
		printk(KERN_ERR "Failed at setsockopt(SO_REUSEADDR), result = %d\n", result);
		goto errout;
	}

	result = __sock->ops->setsockopt(__sock, SOL_TCP, TCP_REPAIR, (char *)&sockopt, sizeof(sockopt));
	if (result < 0)
	{
		printk(KERN_ERR "Failed at setsockopt(TCP_REPAIR) begin, result = %d\n", result);
		goto errout;
	}

	result = __sock->ops->setsockopt(__sock, SOL_IP, IP_TRANSPARENT, (char *)&sockopt, sizeof(sockopt));
	if (result < 0)
	{
		printk(KERN_ERR "Failed at setsockopt(IP_TRANSPARENT), result = %d\n", result);
		goto errout;
	}

	result = __sock->ops->bind(__sock, (struct sockaddr *)&endpoint->addr, sizeof(endpoint->addr));
	if (result < 0)
	{
		printk(KERN_ERR "Failed at bind(), result = %d\n", result);
		goto errout;
	}

	result = __sock->ops->connect(__sock, (struct sockaddr *)&endpoint->addr, sizeof(endpoint->addr), 0);
	if (result < 0)
	{
		printk(KERN_ERR "Failed at connect(), result = %d\n", result);
		goto errout;
	}

	sockopt = 0;
	result = __sock->ops->setsockopt(__sock, SOL_TCP, TCP_REPAIR, (char *)&sockopt, sizeof(sockopt));
	if (result < 0)
	{
		printk(KERN_ERR "Failed at setsockopt(TCP_REPAIR) end, result = %d\n", result);
		goto errout;
	}

	__file = sock_alloc_file(__sock, O_CLOEXEC, NULL);
	if (__file < 0)
	{
		printk(KERN_ERR "Failed at alloc file\n");
		goto errout;
	}

	__fd = get_unused_fd_flags(O_CLOEXEC);
	if (__fd < 0)
	{
		printk(KERN_ERR "Failed at alloc fd\n");
		goto errout;
	}

	if (likely(!IS_ERR(__file)))
	{
		fd_install(__fd, __file);
	}

	return __fd;

errout:
	return -1;	

}

static int __tcp_restore_from_tcp_restore_info(const struct tcp_restore_info * info)
{
}

static void hexdump(char *note, unsigned char *buf, unsigned int len)
{
	printk(KERN_CRIT "%s", note);
	print_hex_dump(KERN_CONT, "", DUMP_PREFIX_OFFSET, 16, 1, buf, len, false);
}

unsigned int tfe_kernel_tcp_hook_entry(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	/* Filter ClientHello from all incoming packets,
	 * ClientHello may exist in all TCP packets */

	/* Payload */
	unsigned int ip_payload_len;
	const uint8_t * tcp_payload;
	unsigned int tcp_payload_len;

	/* Restore info */
	struct tcp_restore_info __restore_info;

	/* Result */
	int result;

	if(skb_linearize(skb) < 0)
		goto not_mine;

	if(ip_hdr(skb)->protocol != IPPROTO_TCP)
		goto not_mine;

	ip_payload_len = ntohs(ip_hdr(skb)->tot_len);
	if(ip_payload_len <= tcp_hdrlen(skb) + ip_hdrlen(skb))
		goto not_mine;

	tcp_payload = skb_transport_header(skb) + tcp_hdrlen(skb);
	tcp_payload_len = ip_payload_len - (tcp_hdrlen(skb) + ip_hdrlen(skb));

	if(tcp_payload_len < sizeof(char) * 2 + sizeof(uint32_t) * 2)
		goto not_mine;

	/* Leader */
	if(!(tcp_payload[0] == 0x4d && tcp_payload[1] == 0x5a))
		goto not_mine;

	/* Jump after leader */
	tcp_payload += sizeof(char) * 2;
	tcp_payload_len -= sizeof(char) * 2;

	/* Construct restore info from packet */
	 __tcp_restore_info_parse_from_skb(skb, &__restore_info);

	/* ClientHello with leader */
	result = __tcp_restore_info_parse_from_clienthello(tcp_payload, tcp_payload_len, &__restore_info);
	if(result < 0)
		goto not_mine;

	result = __tcp_restore_from_tcp_restore_info(&__restore_info);
	if(result < 0)
		goto not_mine;

not_mine:
	return NF_ACCEPT;
}

static struct socket * tfe_kmod_unixdomain_socket_create(const char * path)
{
	struct sockaddr_un un_addr;
	struct socket * un_sock = NULL;
	int result;

	memset(&un_addr, 0, sizeof(un_addr));
	un_addr.sun_family = AF_UNIX;
	strcpy(un_addr.sun_path, path);

	result = sys_unlink(path);
	if (unlikely(result < 0 && result != -ENOENT))
	{
		printk(KERN_ERR "Failed at removing file %s\n", path);
		goto errout;
	}

       	result = sock_create_kern(local_net_ptr, AF_UNIX, SOCK_STREAM, 0, &un_sock);
	if (unlikely(result < 0))
	{
		printk(KERN_ERR "Failed at creating unixdomain socket for %s\n", un_addr.sun_path);
		goto errout;
	}

	result = un_sock->ops->bind(un_sock, (struct sockaddr *)&un_addr, sizeof(un_addr));
	if (unlikely(result < 0))
	{
		printk(KERN_ERR "Failed at binding unixdomain socket to %s", un_addr.sun_path);
		goto errout;
	}

errout:
	if (un_sock) sock_release(un_sock); 
	return NULL;
}


static int __init tfe_kernel_tcp_restore_init(void) 
{
	int rval;
	struct net_device * netdev;

	printk(KERN_INFO "if_dev_name = %s\n", if_dev_name);

	netdev = dev_get_by_name(&init_net, if_dev_name);
	if(netdev == NULL)
	{
		printk(KERN_ERR "Cannot open device %s\n", if_dev_name);
		goto errout;
	}

	nf_hook_ops_in.hook = tfe_kernel_tcp_hook_entry;
	nf_hook_ops_in.hooknum = NF_INET_PRE_ROUTING;
	nf_hook_ops_in.pf = PF_INET;
	nf_hook_ops_in.dev = netdev;

	rval = nf_register_net_hook(&init_net, &nf_hook_ops_in);
	if (rval < 0)
	{
		printk(KERN_ERR "Couldn't register incoming packets hook!\n");
		return rval;
	}

	g_scm_socket = tfe_kmod_unixdomain_socket_create(str_ctrlmsg_sock_path);
	if (g_scm_socket == NULL)
	{
		printk(KERN_ERR "Couldn't init scm unixdomain socket\n");
		goto errout;
	}

	printk(KERN_INFO "TFE kernel module init success!\n");
	return 0;

errout:
	if(nf_hook_ops_in.hook != NULL)
	{
		nf_unregister_net_hook(&init_net, &nf_hook_ops_in);
	}

	if(g_scm_socket != NULL)
	{
		sock_release(g_scm_socket);
	}

	return -1;
}

static void __exit tfe_kernel_tcp_restore_exit(void) 
{
	nf_unregister_net_hook(&init_net, &nf_hook_ops_in);
	printk(KERN_INFO "Goodbye, World!\n");
}

module_init(tfe_kernel_tcp_restore_init);
module_exit(tfe_kernel_tcp_restore_exit);

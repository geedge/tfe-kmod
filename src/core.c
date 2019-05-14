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
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/file.h>
#include <linux/un.h>
#include <linux/syscalls.h>

#ifndef TFE_KMOD_VERSION
#define TFE_KMOD_VERSION 	"Unknown"
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lu Qiuwen");
MODULE_DESCRIPTION("Tango Frontend Engine Kernel Module");
MODULE_VERSION(TFE_KMOD_VERSION);

#ifdef PATH_MAX
#define TFE_STRING_SIZE PATH_MAX
#else
#define TFE_STRING_SIZE 2048
#endif

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

struct tfe_kmod_instance
{
	/* Path */
	char str_scm_socket_path[PATH_MAX];

	/* Config */
	char ifname_cmsg_input[IFNAMSIZ];
	char ifname_bfd_input[IFNAMSIZ];

	/* Instances */
	struct net * netspace;
	struct socket * scm_socket;
	struct nf_hook_ops nf_hook_ops_cmsg_input;
	struct nf_hook_ops nf_hook_ops_bfd_input;
};

struct tcp_restore_info_endpoint
{
	struct sockaddr_storage addr;
	bool wscale_perm;
	bool timestamp_perm;
	bool sack_perm;
	uint16_t mss;
	uint8_t wscale;
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

#define TCP_RESTORE_TCPOPT_KIND      88
#define TCP_RESTORE_TCPOPT_LENGTH    4

static char * ifname_cmsg = "lo";
static char * ifname_bfd = "lo";
static char * scm_socket = "/var/run/.tfe_kmod_scm_socket";
static struct tfe_kmod_instance tfe_kmod_instance;
struct tfe_kmod_instance * g_tfe_kmod_instance = &tfe_kmod_instance;

module_param(ifname_cmsg, charp, S_IRUGO);
MODULE_PARM_DESC(ifname_cmsg, "Network interface for incoming control message");
module_param(ifname_bfd, charp, S_IRUGO);
MODULE_PARM_DESC(ifname_bfd, "Network interface for BFD keepalive message");
module_param(scm_socket, charp, S_IRUGO);
MODULE_PARM_DESC(scm_socket, "SCM socket file location");

static void __tcp_restore_info_dump_to_log(const struct tcp_restore_info * info)
{
	return;
}

static int __tcp_restore_info_parse_from_skb(struct sk_buff * skb, struct tcp_restore_info * out)
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

	return 0;
}

static int __tcp_restore_info_parse_from_cmsg(const char * data, unsigned int datalen, struct tcp_restore_info * out)
{
	struct tcp_restore_info_header * header = (struct tcp_restore_info_header *)data;
	unsigned int tlv_iter;
	unsigned int nr_tlvs;

	BUG_ON(header->__magic__[0] != 0x4d || header->__magic__[1] != 0x5a);
	nr_tlvs = ntohs(header->nr_tlvs);

	if (unlikely(nr_tlvs >= 256))
	{
		printk(KERN_ERR "Invalid restore info format: numbers of tlvs is larger than 256, drop it.\n");
		goto invalid_format;
	}

	if (unlikely(datalen < sizeof(struct tcp_restore_info_header)))
	{
		printk(KERN_ERR "Invalid restore info format: length is shorter than tlv header, drop it.\n");
		goto invalid_format;
	}

	datalen -= sizeof(struct tcp_restore_info_header);
	data += sizeof(struct tcp_restore_info_header);

	for(tlv_iter = 0; tlv_iter < nr_tlvs; tlv_iter++)
	{
		struct tcp_restore_info_tlv * tlv = (struct tcp_restore_info_tlv *)data;
		uint16_t tlv_type = ntohs(tlv->type);
		uint16_t tlv_length = ntohs(tlv->length);

		unsigned int __length = tlv_length + sizeof(struct tcp_restore_info_tlv);
		if(unlikely(datalen < __length))
		{
			printk(KERN_ERR "Invalid restore info format: left space is smaller than tlv's length, drop it.\n");
			goto invalid_format;
		}


#define __CHECK_TLV_LENGTH(x) do { if(unlikely(x != tlv_length))							\
	printk(KERN_ERR "Invalid restore format: invalid tlv length, should be %u, actually is %u, drop it.\n", 	\
			(unsigned int)tlv_length, (unsigned int)x);  goto invalid_format; } while(0)

		switch(tlv_type)
		{
			case TCP_RESTORE_INFO_TLV_SEQ:
				__CHECK_TLV_LENGTH(sizeof(uint32_t));
				out->global.seq = ntohl(tlv->value_as_uint32[0]);
				break;

			case TCP_RESTORE_INFO_TLV_ACK:
				__CHECK_TLV_LENGTH(sizeof(uint32_t));
				out->global.ack = ntohl(tlv->value_as_uint32[0]);
				break;

			case TCP_RESTORE_INFO_TLV_TS_CLIENT:
				__CHECK_TLV_LENGTH(sizeof(uint8_t));
				out->client.timestamp_perm = !!(tlv->value_as_uint8[0]);
				break;

			case TCP_RESTORE_INFO_TLV_TS_SERVER:
				__CHECK_TLV_LENGTH(sizeof(uint8_t));
				out->server.timestamp_perm = !!(tlv->value_as_uint8[0]);
				break;

			case TCP_RESTORE_INFO_TLV_WSACLE_CLIENT:
				__CHECK_TLV_LENGTH(sizeof(uint8_t));
				out->client.wscale_perm = true;
				out->client.wscale = tlv->value_as_uint8[0];
				break;

			case TCP_RESTORE_INFO_TLV_WSACLE_SERVER:
				__CHECK_TLV_LENGTH(sizeof(uint8_t));
				out->server.wscale_perm = true;
				out->server.wscale = tlv->value_as_uint8[0];
				break;

			case TCP_RESTORE_INFO_TLV_MSS_CLIENT:
				__CHECK_TLV_LENGTH(sizeof(uint16_t));
				out->client.mss = ntohs(tlv->value_as_uint16[0]);
				break;

			case TCP_RESTORE_INFO_TLV_MSS_SERVER:
				__CHECK_TLV_LENGTH(sizeof(uint16_t));
				out->server.mss = ntohs(tlv->value_as_uint16[0]);
				break;

			default:
				printk(KERN_ERR "Invalid restore info format: unsupported type, drop it.\n");
				goto invalid_format;
		}

		data += __length;
		datalen -= __length;
	}

	return 0;

invalid_format:
	return -EINVAL;
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

    result = kernel_sendmsg(un_sock, &msgh, &iv, 1, msglen);
	if(unlikely(result < 0))
	{
		pr_err("Failed at sendmsg to scm unix domain socket, result = %d\n", result);
        return result;
	}

    /* TODO: replace the sys_* functions with ksys_* when use future kernel version */
    sys_close(fd_client);
    sys_close(fd_server);

	return result;
}

static int __tcp_restore_fd_create(struct net * netspace, const struct tcp_restore_info_endpoint * endpoint, 
		const struct tcp_restore_info_endpoint * peer)
{
	struct socket * __sock;
	struct file * __file;
	int __fd;

	int result;
	int sockopt;

	result = sock_create_kern(netspace, AF_INET, SOCK_STREAM, IPPROTO_TCP, &__sock);
	if (unlikely(result < 0))
	{
		printk(KERN_ERR "Failed at creating client's socket at kern\n");
		goto errout;
	}

	sockopt = 1;

	/* Setup TCP REPAIR Status */
	result = kernel_setsockopt(__sock, SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));
	if (unlikely(result < 0))
	{
		printk(KERN_ERR "Failed at setsockopt(SO_REUSEADDR), result = %d\n", result);
		goto errout;
	}

	result = kernel_setsockopt(__sock, SOL_TCP, TCP_REPAIR, (char *)&sockopt, sizeof(sockopt));
	if (unlikely(result < 0))
	{
		printk(KERN_ERR "Failed at setsockopt(TCP_REPAIR) begin, result = %d\n", result);
		goto errout;
	}

	result = kernel_setsockopt(__sock, SOL_IP, IP_TRANSPARENT, (char *)&sockopt, sizeof(sockopt));
	if (unlikely(result < 0))
	{
		printk(KERN_ERR "Failed at setsockopt(IP_TRANSPARENT), result = %d\n", result);
		goto errout;
	}

	result = kernel_bind(__sock, (struct sockaddr *)&endpoint->addr, sizeof(endpoint->addr));
	if (unlikely(result < 0))
	{
		printk(KERN_ERR "Failed at bind(), result = %d\n", result);
		goto errout;
	}

	result = kernel_connect(__sock, (struct sockaddr *)&endpoint->addr, sizeof(endpoint->addr), 0);
	if (unlikely(result < 0))
	{
		printk(KERN_ERR "Failed at connect(), result = %d\n", result);
		goto errout;
	}

	sockopt = 0;
	result = kernel_setsockopt(__sock, SOL_TCP, TCP_REPAIR, (char *)&sockopt, sizeof(sockopt));
	if (unlikely(result < 0))
	{
		printk(KERN_ERR "Failed at setsockopt(TCP_REPAIR) end, result = %d\n", result);
		goto errout;
	}

    /* alloc a new fd */
	__fd = get_unused_fd_flags(O_CLOEXEC);
	if (unlikely(__fd < 0))
	{
		pr_err("Failed at get_unused_fd_flags(), result = %d\n", __fd);
		goto errout;
	}

    /* __sock's ownership is transfered to __file */
	__file = sock_alloc_file(__sock, O_CLOEXEC, NULL);
    __sock = NULL;

	if (unlikely(IS_ERR(__file)))
	{
		pr_err("Failed at sock_alloc_file(), result = %ld\n", PTR_ERR(__file));
		result = PTR_ERR(__file); goto errout;
	}

    fd_install(__fd, __file);
    return __fd;

errout:
    if(unlikely(__fd > 0))
    {
        put_unused_fd(__fd);
    }

    if(unlikely(__sock != NULL))
    {
        sock_release(__sock);
    }

    return result;
}

static inline bool is_ipv4_pkt(const struct sk_buff * skb)
{
    return skb->protocol == htons(ETH_P_IP) && ip_hdr(skb)->version == 4;
}

static inline bool is_ipv6_pkt(const struct sk_buff * skb)
{
    return skb->protocol == htons(ETH_P_IPV6) && ipv6_hdr(skb)->version == 6;
}

static bool tcp_find_option(uint8_t option, const struct sk_buff *skb,
		unsigned int protoff, unsigned int optlen, uint8_t * out_optlen, 
        char * out_optvalue, unsigned int out_optvalue_len)
{
	/* tcp.doff is only 4 bits, ie. max 15 * 4 bytes */
	const uint8_t *op;
	uint8_t _opt[60 - sizeof(struct tcphdr)];
	unsigned int i;

	pr_debug("finding option\n");

	if (!optlen)
		return false;

	/* If we don't have the whole header, drop packet. */
	op = skb_header_pointer(skb, protoff + sizeof(struct tcphdr), optlen, _opt);
	if (op == NULL) 
	{
		return false;
	}

	for (i = 0; i < optlen; )
	{
        uint8_t __optlen;
        uint8_t __valuelen;

		if (op[i] == option)
        {
            if(op[i] < 2)
            {
                *out_optlen = 0;
                return true;
            }

            __optlen = op[i+1];
            if(unlikely(__optlen <= 2))
            {
                pr_err_ratelimited("Invalid tcp option length, must be larger than 2, but the value is %u\n", __optlen);
                return false;
            }

            __valuelen = __optlen - 2;
            if(unlikely(__valuelen > out_optvalue_len))
            {
                pr_warn_ratelimited("tcp option length is larger input buffer\n");
                return false;
            }

            *out_optlen = __valuelen;
            memcpy(out_optvalue, &op[i+2], __valuelen);
            return true;
        }

		if (op[i] < 2) i++;
		else i += op[i+1]?:1;
	}

	return false;
}

unsigned int tfe_kernel_tcp_hook_entry(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	/* Filter ClientHello from all incoming packets,
	 * ClientHello may exist in all TCP packets */

    struct tfe_kmod_instance * instance;

    /* TCP header */
    struct tcphdr _tcp_hdr;
    struct tcphdr * tcp_hdr;
    unsigned int tcp_hdr_len;

    /* TCP Options */
    uint32_t restore_tcpopt_value;
    uint8_t restore_tcpopt_length;
    bool is_hit_tcpopt;

	const uint8_t * tcp_payload;
	unsigned int tcp_payload_len;
    const uint8_t * cmsg_payload;
    unsigned int cmsg_payload_len;

	/* Restore info */
	struct tcp_restore_info __restore_info;
	/* Result */
	int result;

    /* FDs */
    int fd_client = 0;
    int fd_server = 0;

    instance = (struct tfe_kmod_instance *)priv;
    BUG_ON(instance->netspace != NULL);

    if(skb->protocol == htons(ETH_P_IP))
    {
        struct iphdr _ip_hdr;
        struct iphdr * ip_hdr;
        
        ip_hdr = skb_header_pointer(skb, skb_network_offset(skb), sizeof(_ip_hdr), &_ip_hdr);

        /* Not continous at IP header, or not TCP protocol, ignore it */
        if (!ip_hdr || ip_hdr->version != 4 || ip_hdr->protocol != IPPROTO_TCP)
        {
            goto not_mine;
        }
    }
    else if(skb->protocol == htons(ETH_P_IPV6))
    {
        struct ipv6hdr _ipv6_hdr;
        struct ipv6hdr * ipv6_hdr;

        ipv6_hdr = skb_header_pointer(skb, skb_network_offset(skb), sizeof(_ipv6_hdr), &_ipv6_hdr);

        /* Not continous at IPv6 header, or not TCP protocol, ignore it */
        if (!ipv6_hdr || ipv6_hdr->version != 6 || ipv6_hdr->nexthdr != IPPROTO_TCP)
        {
            goto not_mine;
        }
    }
    else
    {
        goto not_mine;
    }

    tcp_hdr = skb_header_pointer(skb, skb_transport_offset(skb), sizeof(_tcp_hdr), &_tcp_hdr);
    tcp_hdr_len = tcp_hdr->doff * 4;

    /* Check if there is a tcp options */
    if(!tcp_hdr || tcp_hdr_len <= sizeof(struct tcphdr))
    {
        goto not_mine;
    }

    is_hit_tcpopt = tcp_find_option(TCP_RESTORE_TCPOPT_KIND, skb, skb_transport_offset(skb),
            tcp_hdr_len - sizeof(struct tcphdr), &restore_tcpopt_length, 
            (char *)&restore_tcpopt_value, sizeof(restore_tcpopt_value));

    if(!is_hit_tcpopt)
    {
        goto not_mine;
    }

    /* TCPOPT match, linearize the skb */
    if(unlikely(skb_linearize(skb) < 0))
    {
        goto errout;
    }

    /* Check */
    BUG_ON(skb_transport_offset(skb) < skb_mac_offset(skb));
    BUG_ON(skb_transport_offset(skb) - skb_mac_offset(skb) < tcp_hdr_len);

    /* TCP Payload */
    tcp_payload = skb_transport_header(skb) + tcp_hdr_len;
    tcp_payload_len = skb_transport_offset(skb) - skb_mac_offset(skb) - tcp_hdr_len;

    /* Cmsg */
    BUG_ON(tcp_payload_len >= restore_tcpopt_value);
    cmsg_payload = tcp_payload + restore_tcpopt_value;
    cmsg_payload_len = tcp_payload_len - restore_tcpopt_value;

	/* Construct restore info from packet */
    result = __tcp_restore_info_parse_from_skb(skb, &__restore_info);
    if(unlikely(result < 0))
    {
        goto errout;
    }

	/* ClientHello with leader */
	result = __tcp_restore_info_parse_from_cmsg(tcp_payload, tcp_payload_len, &__restore_info);
	if(unlikely(result < 0))
    {
        goto errout;
    }

    /* Remove cmsg from clienthello */

    /* Create FDs */
    fd_client = __tcp_restore_fd_create(instance->netspace, &__restore_info.client, &__restore_info.server);
    if(unlikely(fd_client < 0))
    {
        goto errout;
    }

    fd_server = __tcp_restore_fd_create(instance->netspace, &__restore_info.server, &__restore_info.client);
    if(unlikely(fd_server < 0))
    {
        goto errout;
    }

    /* Send FDs to userspace application */
    result = __fd_send_to_tfe_userspace(instance->scm_socket, fd_client, fd_server, NULL, 0);
    if(unlikely(result < 0))
    {
        goto errout;
    }


errout:
    if(unlikely(fd_client > 0))
    {
        sys_close(fd_client);
    }

    if(unlikely(fd_server > 0))
    {
        sys_close(fd_server);
    }

    return NF_ACCEPT;

not_mine:
	return NF_ACCEPT;
}

static int __netfilter_ops_register(struct net * netspace, 
		struct nf_hook_ops * ops, const char * ifname, nf_hookfn * fn, void * arg)
{
	struct net_device * netdev;
	int result;

	printk(KERN_DEBUG "netfilter ops register, ifname = %s\n", ifname) ; 
	netdev = dev_get_by_name(&init_net, ifname);

	if(unlikely(netdev == NULL))
	{
		printk(KERN_ERR "cannot find device %s, netfilter register failed.\n", ifname);
		goto errout;
	}

	ops->hook = fn;
	ops->hooknum = NF_INET_PRE_ROUTING;
	ops->pf = PF_INET;
	ops->dev = netdev;

	result = nf_register_net_hook(&init_net, ops);
	if (unlikely(result < 0))
	{
		printk(KERN_ERR "cannot register netfilter ops for device %s, result = %d\n", ifname, result);
		goto errout;
	}

	return result;

errout:
	if(netdev != NULL) dev_put(netdev);
	return result;
}

static struct socket * tfe_kmod_unixdomain_socket_create(struct net * netspace, const char * path)
{
	struct sockaddr_un un_addr;
	struct socket * un_sock = NULL;
	int result;

	memset(&un_addr, 0, sizeof(un_addr));
	un_addr.sun_family = AF_UNIX;
	strcpy(un_addr.sun_path, path);

	result = sys_unlinkat(AT_FDCWD, un_addr.sun_path, 0);
	if (unlikely(result < 0 && result != -ENOENT))
	{
		printk(KERN_ERR "Failed at removing file %s\n", path);
		goto errout;
	}
       	
	result = sock_create_kern(netspace, AF_UNIX, SOCK_DGRAM, 0, &un_sock);
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

	return un_sock;

errout:
	if (un_sock) sock_release(un_sock); 
	return NULL;
}

static int tfe_kmod_instance_init(struct tfe_kmod_instance * instance)
{
	instance->netspace = &init_net;
	instance->scm_socket = tfe_kmod_unixdomain_socket_create(instance->netspace, instance->str_scm_socket_path);
	if (unlikely(instance->scm_socket != NULL))
	{
		pr_err("Failed at creating scm socket for %s\n", instance->str_scm_socket_path);
		return -1;
	}

	return 0;
}

static int tfe_kmod_instance_deinit(struct tfe_kmod_instance * instance)
{
	return 0;
}

static int __init tfe_kmod_init(void) 
{
	int result;

	printk(KERN_INFO "Tango Frontend Engine Kernel Module, Version: %s\n", TFE_KMOD_VERSION);

	strlcpy(g_tfe_kmod_instance->ifname_cmsg_input, ifname_cmsg, sizeof(g_tfe_kmod_instance->ifname_cmsg_input));
	strlcpy(g_tfe_kmod_instance->ifname_cmsg_input, ifname_bfd, sizeof(g_tfe_kmod_instance->ifname_bfd_input));

	result = tfe_kmod_instance_init(g_tfe_kmod_instance);
	if (unlikely(result < 0))
	{
		pr_err("Tango Frontend Engine - KMOD init failed.");
		return result;
	}

	pr_info("Tango Frontend Engine Kernel Module init success.\n");
	return 0;
}

static void __exit tfe_kmod_exit(void) 
{
	tfe_kmod_instance_deinit(g_tfe_kmod_instance);
}

module_init(tfe_kmod_init);
module_exit(tfe_kmod_exit);

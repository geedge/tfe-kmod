#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/netfilter.h>
#include <linux/if.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/file.h>
#include <linux/un.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <net/inet_hashtables.h>
#include <net/ip.h>
#include <net/tcp.h>

#include "cmsg.h"

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

struct tfe_kmod_instance
{
    /* Path */
    char str_scm_socket_path[PATH_MAX];
    struct sockaddr_un sk_scm_socket_path;

    /* Config */
    char ifname_cmsg_input[IFNAMSIZ];
    char ifname_bfd_input[IFNAMSIZ];

    /* Instances */
    struct net * netspace;
    struct socket * scm_socket;
    struct nf_hook_ops nf_hook_ops_cmsg_input;
    struct nf_hook_ops nf_hook_ops_bfd_input;
    struct net_device * netdev_cmsg_input;
    struct net_device * netdev_bfd_input;

    /* workqueue */
    struct kthread_worker * k_worker;
};

static char * ifname_cmsg = "lo";
static char * ifname_bfd = "lo";
static char * scm_socket = "/var/run/.tfe_kmod_scm_socket";
static char * scm_socket_kern = "/var/run/.tfe_kmod_scm_socket_kern";
static unsigned int fd_so_mask = 0x65;

static const char * rm_program_path = "/bin/rm";
static char * rm_program_envp[] = { "HOME=/", "TERM=linux", "PATH=/usr/bin:/bin", NULL };

static struct tfe_kmod_instance tfe_kmod_instance;
struct tfe_kmod_instance * g_tfe_kmod_instance = &tfe_kmod_instance;

module_param(ifname_cmsg, charp, S_IRUGO);
MODULE_PARM_DESC(ifname_cmsg, "Network interface for incoming control message");
module_param(ifname_bfd, charp, S_IRUGO);
MODULE_PARM_DESC(ifname_bfd, "Network interface for BFD keepalive message");
module_param(scm_socket, charp, S_IRUGO);
MODULE_PARM_DESC(scm_socket, "SCM socket file location");

static int __call_sys_close(int fd)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
    return ksys_close(fd);
#else
    return sys_close(fd);
#endif
}

static inline bool is_ipv4_pkt(const struct sk_buff * skb)
{
    return skb->protocol == htons(ETH_P_IP) && ip_hdr(skb)->version == 4;
}

static inline bool is_ipv6_pkt(const struct sk_buff * skb)
{
    return skb->protocol == htons(ETH_P_IPV6) && ipv6_hdr(skb)->version == 6;
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
    int result = 0;
    int retried = 0;

    struct kvec iv;
    iv.iov_base = (void *)msg;
    iv.iov_len = msglen;
  
    memset(&msgh, 0, sizeof(msgh));
    msgh.msg_name = NULL;
    msgh.msg_namelen = 0;
    msgh.msg_control = controlMsg.buf;
    msgh.msg_controllen = sizeof(controlMsg.buf);
    msgh.msg_flags = MSG_DONTWAIT;

    memset(controlMsg.buf, 0, sizeof(controlMsg.buf));
    cmsgp = CMSG_FIRSTHDR(&msgh);
    cmsgp->cmsg_len = CMSG_LEN(sizeof(int) * 2);
    cmsgp->cmsg_level = SOL_SOCKET;
    cmsgp->cmsg_type = SCM_RIGHTS;

    ((int *) CMSG_DATA(cmsgp))[0] = fd_server;
    ((int *) CMSG_DATA(cmsgp))[1] = fd_client;


_retry:
    result = kernel_sendmsg(un_sock, &msgh, &iv, 1, msglen);
    if(unlikely(result == -ENOTCONN && retried == 0))
    {
        result = kernel_connect(un_sock, (struct sockaddr *) &g_tfe_kmod_instance->sk_scm_socket_path, 
                sizeof(g_tfe_kmod_instance->sk_scm_socket_path), 0);

        if(unlikely(result < 0))
        {
            pr_err("retry to connect to scm_socket %s err, result = %d\n", 
                    g_tfe_kmod_instance->sk_scm_socket_path.sun_path, result);
        }

        retried = 1;
        goto _retry;
    }

    if(unlikely(result < 0))
    {
        pr_err("Failed at sendmsg to scm unix domain socket, result = %d\n", result);
        return result;
    }

    __call_sys_close(fd_client);
    __call_sys_close(fd_server);

    return result;
}

static int __tcp_restore_fd_create(struct net * netspace, const struct tcp_restore_info_endpoint * endpoint, 
        const struct tcp_restore_info_endpoint * peer)
{
    struct socket * __sock;
    struct file * __file;
    int __fd = 0;

    int result;
    int sockopt;

    struct tcp_repair_opt tcp_repair_opts[8];
    unsigned int nr_tcp_repair_opts = 0;

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

    result = kernel_setsockopt(__sock, SOL_IP, IP_TRANSPARENT, (char *)&sockopt, sizeof(sockopt));
    if (unlikely(result < 0))
    {
        printk(KERN_ERR "Failed at setsockopt(IP_TRANSPARENT), result = %d\n", result);
        goto errout;
    }

    result = kernel_setsockopt(__sock, SOL_TCP, TCP_REPAIR, (char *)&sockopt, sizeof(sockopt));
    if (unlikely(result < 0))
    {
        printk(KERN_ERR "Failed at setsockopt(TCP_REPAIR) begin, result = %d\n", result);
        goto errout;
    }

    sockopt = fd_so_mask;
    result = kernel_setsockopt(__sock, SOL_SOCKET, SO_MARK, (char *)&sockopt, sizeof(sockopt));
    if (unlikely(result < 0))
    {
        printk(KERN_ERR "Failed at setsockopt(SO_MARK), result = %d\n", result);
        goto errout;
    }

    /* Setup SEQ/ACK and TCP options */
    sockopt = TCP_SEND_QUEUE;
    result = kernel_setsockopt(__sock, SOL_TCP, TCP_REPAIR_QUEUE, (char *)&sockopt, sizeof(sockopt));
    if (unlikely(result < 0))
    {
        printk(KERN_ERR "Failed at setsockopt(TCP_REPAIR_QUEUE), result = %d\n", result);
        goto errout;
    }

    sockopt = endpoint->seq;
    result = kernel_setsockopt(__sock, SOL_TCP, TCP_QUEUE_SEQ, (char *)&sockopt, sizeof(sockopt));
    if (unlikely(result < 0))
    {
        printk(KERN_ERR "Failed at setsockopt(TCP_QUEUE_SEQ), result = %d\n", result);
        goto errout;
    }

    sockopt = TCP_RECV_QUEUE;
    result = kernel_setsockopt(__sock, SOL_TCP, TCP_REPAIR_QUEUE, (char *)&sockopt, sizeof(sockopt));
    if (unlikely(result < 0))
    {
        printk(KERN_ERR "Failed at setsockopt(TCP_QUEUE_SEQ), result = %d\n", result);
        goto errout;
    }

    sockopt = endpoint->ack;
    result = kernel_setsockopt(__sock, SOL_TCP, TCP_QUEUE_SEQ, (char *)&sockopt, sizeof(sockopt));
    if (unlikely(result < 0))
    {
        printk(KERN_ERR "Failed at setsockopt(TCP_QUEUE_SEQ), result = %d\n", result);
        goto errout;
    }

#ifndef TCPOPT_MAXSEG
#define TCPOPT_MAXSEG            2
#endif

#ifndef TCPOPT_WINDOW
#define TCPOPT_WINDOW            3
#endif

#ifndef TCPOPT_SACK_PERMITTED
#define TCPOPT_SACK_PERMITTED    4
#endif

    tcp_repair_opts[nr_tcp_repair_opts].opt_code = TCPOPT_MAXSEG;
    tcp_repair_opts[nr_tcp_repair_opts].opt_val = min(endpoint->mss, peer->mss);
    nr_tcp_repair_opts++;

    if (endpoint->sack_perm && peer->sack_perm)
    {
        tcp_repair_opts[nr_tcp_repair_opts].opt_code = TCPOPT_SACK_PERMITTED;
        tcp_repair_opts[nr_tcp_repair_opts].opt_val = 0;
        nr_tcp_repair_opts++;
    }

    if (endpoint->wscale_perm)
    {
        tcp_repair_opts[nr_tcp_repair_opts].opt_code = TCPOPT_WINDOW;
        tcp_repair_opts[nr_tcp_repair_opts].opt_val = (endpoint->wscale << 16 ) | peer->wscale;
        nr_tcp_repair_opts++;
    }

    /* Bind address and connect to peer endpoint */
    result = kernel_bind(__sock, (struct sockaddr *)&endpoint->addr, sizeof(endpoint->addr));
    if (unlikely(result < 0))
    {
        printk(KERN_ERR "Failed at bind(), result = %d\n", result);
        goto errout;
    }

    result = kernel_connect(__sock, (struct sockaddr *)&peer->addr, sizeof(peer->addr), 0);
    if (unlikely(result < 0))
    {
        printk(KERN_ERR "Failed at connect(), result = %d\n", result);
        goto errout;
    }

    result = kernel_setsockopt(__sock, SOL_TCP, TCP_REPAIR_OPTIONS, (char *)tcp_repair_opts, 
            nr_tcp_repair_opts * sizeof(struct tcp_repair_opt));

    if (unlikely(result < 0))
    {
        printk(KERN_ERR "Failed at setsockopt(TCP_REPAIR_OPTIONS), result = %d\n", result);
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

static bool tcp_find_option(uint8_t option, const struct sk_buff *skb,
        unsigned int protoff, unsigned int optlen, uint8_t * out_optlen, 
        char * out_optvalue, unsigned int out_optvalue_len)
{
    /* tcp.doff is only 4 bits, ie. max 15 * 4 bytes */
    const uint8_t *op;
    uint8_t _opt[60 - sizeof(struct tcphdr)];
    unsigned int i;

    pr_debug("skb=%p, protooff=%u, optlen=%u\n", skb, protoff, optlen);

    if (!optlen)
        return false;

    /* If we don't have the whole header, drop packet. */
    op = skb_header_pointer(skb, protoff + sizeof(struct tcphdr), optlen, _opt);
    if (op == NULL) 
    {
        pr_debug("skb=%p, don't have whole header, ignore it.\n", skb);
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

void tfe_kernel_tcp_restore_wkqueue_entry(struct kthread_work * wk)
{
    struct tcp_restore_info * restore_info = container_of(wk, struct tcp_restore_info, kthread_work);
    struct tfe_kmod_instance * instance = restore_info->instance;

    int fd_client = 0;
    int fd_server = 0;
    int result = 0;

    /* Create FDs */
    fd_client = __tcp_restore_fd_create(instance->netspace, &restore_info->client, &restore_info->server);
    if(unlikely(fd_client < 0))
    {
        goto errout;
    }

    fd_server = __tcp_restore_fd_create(instance->netspace, &restore_info->server, &restore_info->client);
    if(unlikely(fd_server < 0))
    {
        goto errout;
    }

    /* Send FDs to userspace application */
    result = __fd_send_to_tfe_userspace(instance->scm_socket, fd_client, fd_server, 
            restore_info->cmsg, restore_info->cmsg_len);

    if(unlikely(result < 0))
    {
        goto errout;
    }

    pr_debug("workqueue process done:\n");
    tcp_restore_info_dump_to_log(restore_info);
    goto out;

errout:
    pr_debug("workqueue error, result = %d\n", result);
    goto out;

out:
    kfree(restore_info);
    return;
}


static bool __has_cmsg_repeat_tag(const struct sk_buff * skb)
{
    const char * mark_in_char = (const char *)&skb->mark;
    return mark_in_char[0] == 0x4d && mark_in_char[1] == 0x5a;
}

static void __set_cmsg_repeat_tag(struct sk_buff * skb)
{
    char * mark_in_char = (char *)&skb->mark;
    mark_in_char[0] = 0x4d;
    mark_in_char[1] = 0x5a;
    mark_in_char[2] = 4;
    mark_in_char[3] = 0;
}

static bool __is_cmsg_exceed_ttl(struct sk_buff * skb)
{
    char * mark_in_char = (char *)&skb->mark;
    return !!(mark_in_char[2] == 0);
}

static void __set_cmsg_decrase_ttl(struct sk_buff * skb)
{
    char * mark_in_char = (char *)&skb->mark;
    mark_in_char[2]--;
}

unsigned int tfe_kernel_tcp_hook_entry(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    /* Filter ClientHello from all incoming packets,
    * ClientHello may exist in all TCP packets */

    struct tfe_kmod_instance * instance;

    /* IP total len */
    uint16_t * p_ip_total_len;
    struct iphdr * ip_hdr = NULL;
    struct ipv6hdr * ipv6_hdr = NULL;

    /* TCP header */
    struct tcphdr _tcp_hdr;
    struct tcphdr * tcp_hdr;
    unsigned int tcp_hdr_len;

    /* TCP Options */
    uint16_t restore_tcpopt_value;
    uint8_t restore_tcpopt_length;
    bool is_hit_tcpopt;

    const uint8_t * tcp_payload;
    unsigned int tcp_payload_len;
    const uint8_t * cmsg_payload;
    unsigned int cmsg_payload_len;

    /* Restore info */
    struct tcp_restore_info * restore_info = NULL;
    /* Result */
    int result = 0;

    instance = (struct tfe_kmod_instance *)priv;
    BUG_ON(instance == NULL || instance->netspace == NULL);

    if(state->in->ifindex != instance->netdev_cmsg_input->ifindex)
    {
        goto not_mine;
    }

    /* The cmsg is re-entry again or not, if the cmsg entry again, check the ttl */
    if(__has_cmsg_repeat_tag(skb) && __is_cmsg_exceed_ttl(skb))
    {
        return NF_DROP;
    }

    if(skb->protocol == htons(ETH_P_IP))
    {
        struct iphdr _ip_hdr;
        ip_hdr = skb_header_pointer(skb, skb_network_offset(skb), sizeof(_ip_hdr), &_ip_hdr);

        /* Not continous at IP header, or not TCP protocol, ignore it */
        if (!ip_hdr || ip_hdr->version != 4 || ip_hdr->protocol != IPPROTO_TCP)
        {
            goto not_mine;
        }

        p_ip_total_len = &ip_hdr->tot_len;
    }
    else if(skb->protocol == htons(ETH_P_IPV6))
    {
        struct ipv6hdr _ipv6_hdr;
        ipv6_hdr = skb_header_pointer(skb, skb_network_offset(skb), sizeof(_ipv6_hdr), &_ipv6_hdr);

        /* Not continous at IPv6 header, or not TCP protocol, ignore it */
        if (!ipv6_hdr || ipv6_hdr->version != 6 || ipv6_hdr->nexthdr != IPPROTO_TCP)
        {
            goto not_mine;
        }

        p_ip_total_len = &ipv6_hdr->payload_len;
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

    if(!is_hit_tcpopt || restore_tcpopt_length != 2)
    {
        goto not_mine;
    }

    restore_tcpopt_value = ntohs(restore_tcpopt_value);

    /* If the cmsg is re-entryed, check if the socket has been created by looking up 
     * the tcp connection table. if not, make the cmsg re-entry the function */

    if(__has_cmsg_repeat_tag(skb) && skb->protocol == ntohs(ETH_P_IP))
    {
        struct sock * sk_lookup = inet_lookup_established(instance->netspace, &tcp_hashinfo, 
                ip_hdr->saddr, tcp_hdr->source, ip_hdr->daddr, tcp_hdr->dest, 0);

        if(sk_lookup == NULL)
        {
            __set_cmsg_decrase_ttl(skb);
            return NF_REPEAT;
        }
        else
        {
            sock_put(sk_lookup);
            return NF_ACCEPT;
        }
    }
    else if(__has_cmsg_repeat_tag(skb) && skb->protocol == ntohs(ETH_P_IPV6))
    {
        BUG();        
    }

    /* TCPOPT match, linearize the skb */
    if(unlikely(skb_linearize(skb) < 0))
    {
        goto errout;
    }

    /* Begin to construct restore information, only happends on cmsg arrivals at first time */
    BUG_ON(!(skb_transport_header(skb) != NULL));
    BUG_ON(!(skb->len >= (skb_transport_offset(skb) + tcp_hdr_len)));

    /* TCP Payload */
    tcp_payload = skb_transport_header(skb) + tcp_hdr_len;
    tcp_payload_len = skb->len - skb_transport_offset(skb) - tcp_hdr_len;

    /* Cmsg */
    BUG_ON(tcp_payload_len < restore_tcpopt_value);
    cmsg_payload = tcp_payload + restore_tcpopt_value;
    cmsg_payload_len = tcp_payload_len - restore_tcpopt_value;

    restore_info = (struct tcp_restore_info *)kmalloc(sizeof(struct tcp_restore_info), GFP_ATOMIC);
    if(unlikely(restore_info == NULL))
    {
        pr_err("Failed at alloc memory for restore info, drop it.\n");
        goto errout;
    }

    /* Init the restore info */
    kthread_init_work(&restore_info->kthread_work, tfe_kernel_tcp_restore_wkqueue_entry);
    restore_info->instance = instance;

    /* Construct restore info from packet */
    result = tcp_restore_info_parse_from_skb(skb, restore_info);
    if(unlikely(result < 0))
    {
        goto errout;
    }

    /* ClientHello with leader */
    result = tcp_restore_info_parse_from_cmsg(cmsg_payload, cmsg_payload_len, restore_info);
    if(unlikely(result < 0))
    {
        goto errout;
    }

    /* Remove cmsg from clienthello, trim the skb and ip payload length */
    skb_trim(skb, skb->len - cmsg_payload_len);
    *p_ip_total_len = htons(ntohs(*p_ip_total_len) - cmsg_payload_len);
    skb->csum_valid = 1;

    /* Defer the tcp restore workload, and make the cmsg re-entry the hook again */
    tcp_restore_info_dump_to_log(restore_info);
    kthread_queue_work(instance->k_worker, &restore_info->kthread_work);

    /* Set the skb with cmsg tag */
    __set_cmsg_repeat_tag(skb);
    return NF_REPEAT;

errout:
    if(restore_info != NULL)
    {
        kfree(restore_info);
    }

    return NF_ACCEPT;

not_mine:
    return NF_ACCEPT;
}

static int __rlimit_fs(struct task_struct *tsk, unsigned int fs_limit)
{
	int retval = 0;
	if (fs_limit > 65536)
    {
        return -EPERM;
	}

	/* protect tsk->signal and tsk->sighand from disappearing */
	if (!tsk->sighand)
    {
		retval = -ESRCH;
		goto out;
	}

	task_lock(tsk->group_leader);
    tsk->signal->rlim[RLIMIT_NOFILE].rlim_cur = fs_limit;
    tsk->signal->rlim[RLIMIT_NOFILE].rlim_max = fs_limit;
	task_unlock(tsk->group_leader);

out:
	return retval;
}

static int __netfilter_ops_register(struct net * netspace, 
        struct nf_hook_ops * ops, const char * ifname, nf_hookfn * fn, void * arg)
{
    int result = 0;
    
    ops->hook = fn;

    ops->hooknum = NF_INET_PRE_ROUTING;
    ops->pf = PF_INET;
    ops->dev = NULL;
    ops->priv = arg;

    result = nf_register_net_hook(netspace, ops);
    if (unlikely(result < 0))
    {
        pr_err("cannot register netfilter ops for device %s, result = %d\n", ifname, result);
        goto errout;
    }

    return result;

errout:
    return result;
}

static struct socket * __scm_socket_create(struct net * netspace, const char * path)
{
    struct sockaddr_un un_addr;
    struct sockaddr_un un_addr_target;

    struct socket * un_sock = NULL;
    int result;

    char * rm_ops_argv[] = 
    {
        (char *)rm_program_path,
        "-f",
        (char *)path,
        NULL
    };

    memset(&un_addr, 0, sizeof(un_addr));
    un_addr.sun_family = AF_UNIX;
    strcpy(un_addr.sun_path, path);

    memset(&un_addr_target, 0, sizeof(un_addr_target));
    un_addr_target.sun_family = AF_UNIX;
    strcpy(un_addr_target.sun_path, g_tfe_kmod_instance->str_scm_socket_path);

    pr_debug("%s %s %s\n", rm_program_path, "-f", path);
    result = call_usermodehelper(rm_program_path, rm_ops_argv, rm_program_envp, UMH_WAIT_PROC);

    if (unlikely(result < 0))
    {
        printk(KERN_ERR "Failed at removing file %s, result = %d\n", path, result);
        goto errout;
    }
       	
    result = sock_create_kern(netspace, AF_UNIX, SOCK_DGRAM, 0, &un_sock);
    if (unlikely(result < 0))
    {
        printk(KERN_ERR "Failed at creating unixdomain socket for %s\n", un_addr.sun_path);
        goto errout;
    }

    result = kernel_connect(un_sock, (struct sockaddr *)&un_addr_target, sizeof(un_addr_target), 0);
    if (unlikely(result == -ENOTCONN))
    {
        goto success;
    }

    if (unlikely(result < 0))
    {
        printk(KERN_ERR "Failed at connection unixdomain socket to %s\n", un_addr_target.sun_path);
        goto errout;
    }

success:
    return un_sock;

errout:
    if (un_sock) sock_release(un_sock); 
    return NULL;
}

static int tfe_kmod_instance_deinit(struct tfe_kmod_instance * instance)
{
    if(instance->scm_socket != NULL)
    {
        sock_release(instance->scm_socket);
    }

    if(instance->nf_hook_ops_cmsg_input.hook)
    {
        nf_unregister_net_hook(instance->netspace, &instance->nf_hook_ops_cmsg_input);
    }

    if(instance->nf_hook_ops_bfd_input.hook)
    {
        nf_unregister_net_hook(instance->netspace, &instance->nf_hook_ops_bfd_input);
    }

    if(instance->netdev_bfd_input)
    {
        dev_put(instance->netdev_bfd_input);
    }

    if(instance->netdev_cmsg_input)
    {
        dev_put(instance->netdev_cmsg_input);
    }

    if(instance->k_worker)
    {
        kthread_destroy_worker(instance->k_worker);
    }

    return 0;
}

static int tfe_kmod_instance_init(struct tfe_kmod_instance * instance)
{
    int result = 0;

    instance->netspace = &init_net;
    instance->scm_socket = __scm_socket_create(instance->netspace, scm_socket_kern);
    if (instance->scm_socket == NULL)
    {
        pr_err("Failed at creating scm socket for %s\n", scm_socket_kern);
        goto errout;
    }

    instance->sk_scm_socket_path.sun_family = AF_UNIX;
    strcpy(instance->sk_scm_socket_path.sun_path, instance->str_scm_socket_path);

    instance->netdev_cmsg_input = dev_get_by_name(instance->netspace, instance->ifname_cmsg_input);
    if(instance->netdev_cmsg_input == NULL)
    {
        pr_err("Failed at finding cmsg input device %s\n", instance->ifname_cmsg_input);
        goto errout;
    }

    pr_info("CMSG Incoming Interface: %s(%p)\n", instance->netdev_cmsg_input->name, instance->netdev_cmsg_input);

    result = __netfilter_ops_register(instance->netspace, &instance->nf_hook_ops_cmsg_input,
            instance->ifname_cmsg_input, tfe_kernel_tcp_hook_entry, instance);

    if (result < 0)
    {
        pr_err("Failed at register netfilter for cmsg at interface %s\n", instance->ifname_cmsg_input);
        goto errout;
    }

    instance->k_worker = kthread_create_worker(0, "tfe-tcp-restore");
    if(IS_ERR(instance->k_worker))
    {
        pr_err("Failed at creating kthread worker for tcp restore, result = %ld\n", PTR_ERR(instance->k_worker));
        instance->k_worker = NULL; goto errout;
    }

    result = __rlimit_fs(instance->k_worker->task, 65535);
    if(result < 0)
    {
        pr_err("Failed at set NOFILE limit for kthread worker, result = %d\n", result);
        goto errout;
    }

    return 0;

errout:
    tfe_kmod_instance_deinit(instance);
    return -EFAULT;
}

static int __init tfe_kmod_init(void) 
{
    int result;
    pr_info("Tango Frontend Engine Kernel Module, Version: %s\n", TFE_KMOD_VERSION);

    strlcpy(g_tfe_kmod_instance->ifname_cmsg_input, ifname_cmsg, sizeof(g_tfe_kmod_instance->ifname_cmsg_input));
    strlcpy(g_tfe_kmod_instance->ifname_bfd_input, ifname_bfd, sizeof(g_tfe_kmod_instance->ifname_bfd_input));
    strlcpy(g_tfe_kmod_instance->str_scm_socket_path, scm_socket, sizeof(g_tfe_kmod_instance->str_scm_socket_path));

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

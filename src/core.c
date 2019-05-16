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
#include <linux/version.h>

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

    /* Config */
    char ifname_cmsg_input[IFNAMSIZ];
    char ifname_bfd_input[IFNAMSIZ];

    /* Instances */
    struct net * netspace;
    struct socket * scm_socket;
    struct nf_hook_ops nf_hook_ops_cmsg_input;
    struct nf_hook_ops nf_hook_ops_bfd_input;
};

static char * ifname_cmsg = "lo";
static char * ifname_bfd = "lo";
static char * scm_socket = "/var/run/.tfe_kmod_scm_socket";

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
    int result;

    struct kvec iv;
    iv.iov_base = (void *)msg;
    iv.iov_len = msglen;

    memset(&msgh, 0, sizeof(msgh));
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

    /* IP total len */
    uint16_t * p_ip_total_len;

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
    BUG_ON(instance == NULL || instance->netspace == NULL);

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

        p_ip_total_len = &ip_hdr->tot_len;
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
    result = tcp_restore_info_parse_from_skb(skb, &__restore_info);
    if(unlikely(result < 0))
    {
        goto errout;
    }

    /* ClientHello with leader */
    result = tcp_restore_info_parse_from_cmsg(tcp_payload, tcp_payload_len, &__restore_info);
    if(unlikely(result < 0))
    {
        goto errout;
    }

    /* Remove cmsg from clienthello, trim the skb and ip payload length */
    skb_trim(skb, cmsg_payload_len);
    *p_ip_total_len = htons(ntohs(*p_ip_total_len) - cmsg_payload_len);

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
        __call_sys_close(fd_client);
    }

    if(unlikely(fd_server > 0))
    {
        __call_sys_close(fd_server);
    }

    return NF_ACCEPT;

not_mine:
    return NF_ACCEPT;
}

static int __netfilter_ops_register(struct net * netspace, 
        struct nf_hook_ops * ops, const char * ifname, nf_hookfn * fn, void * arg)
{
    struct net_device * netdev;
    int result = 0;

    pr_debug("netfilter ops register, ifname = %s\n", ifname) ; 
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
    ops->priv = arg;

    result = nf_register_net_hook(netspace, ops);
    if (unlikely(result < 0))
    {
        pr_err("cannot register netfilter ops for device %s, result = %d\n", ifname, result);
        goto errout;
    }

    return result;

errout:
    if(netdev != NULL) dev_put(netdev);
    return result;
}

static struct socket * __scm_socket_create(struct net * netspace, const char * path)
{
    struct sockaddr_un un_addr;
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

    result = kernel_bind(un_sock, (struct sockaddr *)&un_addr, sizeof(un_addr));
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

    return 0;
}

static int tfe_kmod_instance_init(struct tfe_kmod_instance * instance)
{
    int result = 0;

    instance->netspace = &init_net;
    instance->scm_socket = __scm_socket_create(instance->netspace, instance->str_scm_socket_path);
    if (instance->scm_socket == NULL)
    {
        pr_err("Failed at creating scm socket for %s\n", instance->str_scm_socket_path);
        goto errout;
    }

    result = __netfilter_ops_register(instance->netspace, &instance->nf_hook_ops_cmsg_input,
            instance->ifname_cmsg_input, tfe_kernel_tcp_hook_entry, instance);

    if (result < 0)
    {
        pr_err("Failed at register netfilter for cmsg at interface %s\n", instance->ifname_cmsg_input);
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
    strlcpy(g_tfe_kmod_instance->ifname_cmsg_input, ifname_bfd, sizeof(g_tfe_kmod_instance->ifname_bfd_input));
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

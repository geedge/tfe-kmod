
#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "cmsg.h"

extern const char * inet_ntop(int af, const void *src, char *dst, size_t size);

void tcp_restore_info_dump_to_log(const struct tcp_restore_info * info)
{
    char str_client_addr[64];
    char str_server_addr[64];

    const struct tcp_restore_info_endpoint * client = &info->client;
    const struct tcp_restore_info_endpoint * server = &info->server;

    BUG_ON(client->addr.ss_family != server->addr.ss_family);
    BUG_ON(client->addr.ss_family != AF_INET && client->addr.ss_family != AF_INET6);

    if(client->addr.ss_family == AF_INET)
    {
        struct sockaddr_in * sk_client = (struct sockaddr_in *)&client->addr;
        struct sockaddr_in * sk_server = (struct sockaddr_in *)&server->addr;
        uint16_t port_client = ntohs(sk_client->sin_port);
        uint16_t port_server = ntohs(sk_server->sin_port);

        inet_ntop(AF_INET, &sk_client->sin_addr, str_client_addr, sizeof(str_client_addr));
        inet_ntop(AF_INET, &sk_server->sin_addr, str_server_addr, sizeof(str_client_addr));

        pr_debug("tcp_restore_info %p: %s:%hu->%s:%hu, seq=%u, ack=%u\n", info, 
                 str_client_addr, port_client, str_server_addr, port_server, info->client.seq, info->client.ack);

    }
    else if(client->addr.ss_family == AF_INET6)
    {
        struct sockaddr_in6 * sk_client = (struct sockaddr_in6 *)&client->addr;
        struct sockaddr_in6 * sk_server = (struct sockaddr_in6 *)&server->addr;
        uint16_t port_client = ntohs(sk_client->sin6_port);
        uint16_t port_server = ntohs(sk_server->sin6_port);

        inet_ntop(AF_INET6, &sk_client->sin6_addr, str_client_addr, sizeof(str_client_addr));
        inet_ntop(AF_INET6, &sk_server->sin6_addr, str_server_addr, sizeof(str_client_addr));

        pr_debug("tcp_restore_info %p: %s:%hu->%s:%hu, seq=%u, ack=%u\n", info, 
                 str_client_addr, port_client, str_server_addr, port_server, info->client.seq, info->client.ack);
    }

    pr_debug("tcp_restore_info %p: client, mss=%u, wscale_perm=%u, wscale=%u, ts=%u, sack=%u\n", 
             info, client->mss, client->wscale_perm ? 1 : 0,
             client->wscale, client->timestamp_perm ? 1 : 0,
             client->sack_perm ? 1 : 0);

    pr_debug("tcp_restore_info %p: server, mss=%u, wscale_perm=%u, wscale=%u, ts=%u, sack=%u\n", 
             info, server->mss, server->wscale_perm ? 1 : 0,
             server->wscale, server->timestamp_perm ? 1 : 0,
             server->sack_perm ? 1 : 0);

    return;
}

int tcp_restore_info_parse_from_skb(struct sk_buff * skb, struct tcp_restore_info * out)
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
    in_addr_server->sin_port = tcphdr->dest;

    return 0;
}

int tcp_restore_info_parse_from_cmsg(const char * data, unsigned int datalen, struct tcp_restore_info * out)
{
    struct tcp_restore_info_header * header = (struct tcp_restore_info_header *)data;
    unsigned int tlv_iter;
    unsigned int nr_tlvs;

    if(unlikely(header->__magic__[0] != 0x4d || header->__magic__[1] != 0x5a))
    {
        pr_err("Invalid restore info format: wrong magic, drop it.\n");
        goto invalid_format;
    }

    nr_tlvs = ntohs(header->nr_tlvs);
    if (unlikely(nr_tlvs >= 256))
    {
        pr_err_ratelimited("Invalid restore info format: numbers of tlvs is larger than 256, drop it.\n");
        goto invalid_format;
    }

    if (unlikely(datalen < sizeof(struct tcp_restore_info_header)))
    {
        printk(KERN_ERR "Invalid restore info format: length is shorter than tlv header, drop it.\n");
        goto invalid_format;
    }

    memcpy(out->cmsg, data, datalen);
    out->cmsg_len = datalen;

    datalen -= sizeof(struct tcp_restore_info_header);
    data += sizeof(struct tcp_restore_info_header);
    
    for(tlv_iter = 0; tlv_iter < nr_tlvs; tlv_iter++)
    {
        struct tcp_restore_info_tlv * tlv = (struct tcp_restore_info_tlv *)data;
        uint16_t tlv_type = ntohs(tlv->type);
        uint16_t tlv_length = ntohs(tlv->length);

        unsigned int __length = tlv_length;
        if(unlikely(datalen < __length))
        {
            printk(KERN_ERR "Invalid restore info format: left space is smaller than tlv's length, "
                    "datalen is %u, tlv's length is %u, drop it.\n", datalen, __length); goto invalid_format;
        }

        if(unlikely(tlv_length < sizeof(uint16_t) * 2))
        {
            printk(KERN_ERR "Invalid restore info format: invalid tlv length, should larger than sizeof(type) + sizeof(length).\n");
            goto invalid_format;
        }

        tlv_length -= sizeof(uint16_t) * 2;

#define __CHECK_TLV_LENGTH(x) do { if(unlikely(x != tlv_length)) {                                              \
    printk(KERN_ERR "Invalid restore format: invalid tlv length, should be %u, actually is %u, drop it.\n", 	\
            (unsigned int)x, (unsigned int)tlv_length);  goto invalid_format; }} while(0)

        switch(tlv_type)
        {
            case TCP_RESTORE_INFO_TLV_SEQ:
                __CHECK_TLV_LENGTH(sizeof(uint32_t));
                out->client.seq = ntohl(tlv->value_as_uint32[0]);
                out->server.ack = ntohl(tlv->value_as_uint32[0]);
                break;

            case TCP_RESTORE_INFO_TLV_ACK:
                __CHECK_TLV_LENGTH(sizeof(uint32_t));
                out->client.ack = ntohl(tlv->value_as_uint32[0]);
                out->server.seq = ntohl(tlv->value_as_uint32[0]);
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

            case TCP_RESTORE_INFO_TLV_SACK_CLIENT:
                __CHECK_TLV_LENGTH(sizeof(uint8_t));
                out->client.sack_perm = true;
                break;

            case TCP_RESTORE_INFO_TLV_SACK_SERVER:
                __CHECK_TLV_LENGTH(sizeof(uint8_t));
                out->server.sack_perm = true;
                break;

            case TCP_RESTORE_INFO_TLV_MSS_CLIENT:
                __CHECK_TLV_LENGTH(sizeof(uint16_t));
                out->client.mss = ntohs(tlv->value_as_uint16[0]);
                break;

            case TCP_RESTORE_INFO_TLV_MSS_SERVER:
                __CHECK_TLV_LENGTH(sizeof(uint16_t));
                out->server.mss = ntohs(tlv->value_as_uint16[0]);
                break;

            case TCP_RESTORE_INFO_TLV_PROTOCOL:
            case TCP_RESTORE_INFO_TLV_USER_DEFINED:
                break;

            default:
                printk(KERN_ERR "Invalid restore info format: unsupported type %x, drop it.\n", tlv_type);
                goto invalid_format;
        }

        data += __length;
        datalen -= __length;
    }

   return 0;

invalid_format:
    pr_err("cmsg parser fail!\n");
    return -EINVAL;
} 

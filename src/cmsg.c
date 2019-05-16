
#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "cmsg.h"

void tcp_restore_info_dump_to_log(const struct tcp_restore_info * info)
{
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
    in_addr_client->sin_port = tcphdr->dest;

    return 0;
}

int tcp_restore_info_parse_from_cmsg(const char * data, unsigned int datalen, struct tcp_restore_info * out)
{
    struct tcp_restore_info_header * header = (struct tcp_restore_info_header *)data;
    unsigned int tlv_iter;
    unsigned int nr_tlvs;

    BUG_ON(header->__magic__[0] != 0x4d || header->__magic__[1] != 0x5a);
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

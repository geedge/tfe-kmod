#pragma once
#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/skbuff.h>

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

struct tcp_restore_info_endpoint
{
    struct sockaddr_storage addr;
    uint32_t seq;
    uint32_t ack;
    bool wscale_perm;
    bool timestamp_perm;
    bool sack_perm;
    uint16_t mss;
    uint8_t wscale;
};

struct tcp_restore_info
{
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


void tcp_restore_info_dump_to_log(const struct tcp_restore_info * info);
int tcp_restore_info_parse_from_skb(struct sk_buff * skb, struct tcp_restore_info * out);
int tcp_restore_info_parse_from_cmsg(const char * data, unsigned int datalen, struct tcp_restore_info * out);

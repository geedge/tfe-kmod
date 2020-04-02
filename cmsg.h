#pragma once
#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/kthread.h>

enum tcp_restore_info_tlv_type
{
    TCP_RESTORE_INFO_TLV_SEQ = 0x0,
    TCP_RESTORE_INFO_TLV_ACK = 0x1,
    TCP_RESTORE_INFO_TLV_MSS_CLIENT = 0x2,
    TCP_RESTORE_INFO_TLV_MSS_SERVER = 0x3,
    TCP_RESTORE_INFO_TLV_WSACLE_CLIENT = 0x4,
    TCP_RESTORE_INFO_TLV_WSACLE_SERVER = 0x5,
    TCP_RESTORE_INFO_TLV_SACK_CLIENT = 0x6,
    TCP_RESTORE_INFO_TLV_SACK_SERVER = 0x7,
    TCP_RESTORE_INFO_TLV_TS_CLIENT = 0x8,
    TCP_RESTORE_INFO_TLV_TS_SERVER = 0x9,
    TCP_RESTORE_INFO_TLV_PROTOCOL = 0xa,
    TCP_RESTORE_INFO_WINDOW_CLIENT = 0xb,
    TCP_RESTORE_INFO_WINDOW_SERVER = 0xc,
    TCP_RESTORE_INFO_PACKET_CUR_DIR = 0xd
};

enum tcp_restore_pkt_cur_dir
{
    PKT_CUR_DIR_C2S = 0x1,
    PKT_CUR_DIR_S2C = 0x2
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
    uint16_t window;
    uint8_t wscale;
};

struct tcp_restore_info
{
    struct tfe_kmod_instance *instance;
    struct kthread_work kthread_work;
    struct nf_queue_entry *nf_queue_entry;

    enum tcp_restore_pkt_cur_dir cur_dir;
    struct tcp_restore_info_endpoint client;
    struct tcp_restore_info_endpoint server;

    char cmsg[2048];
    unsigned int cmsg_len;
};

struct tcp_restore_info_tlv
{
    uint16_t type;
    uint16_t length;

    union {
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

#define TCP_RESTORE_TCPOPT_KIND 88
#define TCP_RESTORE_TCPOPT_LENGTH 4

void tcp_restore_info_dump_to_log(const struct tcp_restore_info *info);
int tcp_restore_info_parse_from_skb(struct sk_buff *skb, struct tcp_restore_info *out);
int tcp_restore_info_parse_from_cmsg(const char *data, unsigned int datalen, struct tcp_restore_info *out);

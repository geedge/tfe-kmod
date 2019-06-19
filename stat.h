#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/net.h>

enum tfe_kmod_stat_item
{
    /* netfilter return value */
    TFE_KMOD_STAT_NF_HOOK_INPUT,
    TFE_KMOD_STAT_NF_HOOK_ACCEPT,
    TFE_KMOD_STAT_NF_HOOK_DROP,
    TFE_KMOD_STAT_NF_HOOK_REPEAT,
    TFE_KMOD_STAT_NF_HOOK_QUEUE,

    /* cmsg */
    TFE_KMOD_STAT_CMSG_NOT_HIT,
    TFE_KMOD_STAT_CMSG_INVALID_FORMAT,
    TFE_KMOD_STAT_CMSG_IN_QUEUE,

    /* CONNECTION */
    TFE_KMOD_STAT_RESTORE_NEW,
    TFE_KMOD_STAT_RESTORE_FAIL_AT_RESTORE,
    TFE_KMOD_STAT_RESTORE_FAIL_AT_SENDMSG,
    TFE_KMOD_STAT_RESTORE_SUCCESS,

    /* Max */
    TFE_KMOD_STAT_MAX
};

struct tfe_kmod_stat;
struct tfe_kmod_stat * tfe_kmod_stat_create(struct net * netspace);
void tfe_kmod_stat_destroy(struct tfe_kmod_stat * stat);
void tfe_kmod_stat_add(struct tfe_kmod_stat * handle, enum tfe_kmod_stat_item st_item, unsigned int value);


#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/net.h>

#include "stat.h"

#ifndef TFE_KMOD_PROC_DIR
#define TFE_KMOD_PROC_DIR "tfe"
#endif

static const char * str_stat_entry[] = 
{
    [TFE_KMOD_STAT_NF_HOOK_INPUT] = "NfHookInput",
    [TFE_KMOD_STAT_NF_HOOK_ACCEPT] = "NfHookAccept",
    [TFE_KMOD_STAT_NF_HOOK_DROP] = "NfHookDrop",
    [TFE_KMOD_STAT_NF_HOOK_REPEAT] = "NfHookRepeat",
    [TFE_KMOD_STAT_NF_HOOK_QUEUE] = "NfHookQueue",
    [TFE_KMOD_STAT_CMSG_NOT_HIT] = "CmsgNotHit",
    [TFE_KMOD_STAT_CMSG_INVALID_FORMAT] = "CmsgInvalidFormat",
    [TFE_KMOD_STAT_CMSG_IN_QUEUE] = "CmsgInQueue",
    [TFE_KMOD_STAT_RESTORE_NEW] = "RestoreNew",
    [TFE_KMOD_STAT_RESTORE_FAIL_AT_RESTORE] = "RestoreFailAtSocketSetup",
    [TFE_KMOD_STAT_RESTORE_FAIL_AT_SENDMSG] = "RestoreFailAtSendMsg",
    [TFE_KMOD_STAT_RESTORE_SUCCESS] = "RestoreSuccess",
    [TFE_KMOD_STAT_MAX] = "Max"
};

struct tfe_kmod_stat
{
    struct proc_dir_entry * proc_dir;
    struct proc_dir_entry * proc_stat_entry;
    atomic64_t stat[TFE_KMOD_STAT_MAX];
};

static int tfe_kmod_stat_show(struct seq_file *seq, void *v)
{
    struct tfe_kmod_stat * stat_handler = (struct tfe_kmod_stat *)seq->private;
    int i = 0;

    for(i = 0; i < TFE_KMOD_STAT_MAX - 1; i++)
    {
        uint64_t value = atomic64_read(&stat_handler->stat[i]);
        seq_printf(seq, "%s\t%lld\n", str_stat_entry[i], value);
    }

    return 0;
}

static int tfe_kmod_stat_open(struct inode *inode, struct file *file)
{
    return single_open(file, tfe_kmod_stat_show, PDE_DATA(inode));
}

static ssize_t tfe_kmod_stat_write(struct file *file, const char __user * user_buffer,
        size_t count, loff_t * offset)
{
    return 0;
}

static struct file_operations stat_fops = 
{
    .open = tfe_kmod_stat_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .write = tfe_kmod_stat_write,
    .release = single_release
};

struct tfe_kmod_stat * tfe_kmod_stat_create(struct net * netspace)
{
    struct tfe_kmod_stat * st_handle = kzalloc(sizeof(struct tfe_kmod_stat), GFP_KERNEL);
    if(unlikely(!st_handle))
    {
        pr_err("cannot alloc memory for tfe_kmod_stat\n");
        goto errout;
    }

    st_handle->proc_dir = proc_mkdir(TFE_KMOD_PROC_DIR, NULL);
    if(unlikely(!st_handle))
    {
        pr_err("cannot create %s procfs entry\n", TFE_KMOD_PROC_DIR);
        goto errout;
    }

    st_handle->proc_stat_entry = proc_create_data("stat", 0600, st_handle->proc_dir, 
            &stat_fops, st_handle);

    if(unlikely(!st_handle->proc_stat_entry))
    {
        pr_err("cannot create %s/%s procfs entry\n", TFE_KMOD_PROC_DIR, "stat");
        goto errout;
    }

    return st_handle;

errout:
    return NULL;
}


void tfe_kmod_stat_add(struct tfe_kmod_stat * handle, enum tfe_kmod_stat_item st_item, unsigned int value)
{
    BUG_ON(st_item >= TFE_KMOD_STAT_MAX);
    atomic64_add(value, &handle->stat[st_item]);
    return;
}

void tfe_kmod_stat_destroy(struct tfe_kmod_stat * stat)
{
    remove_proc_entry("stat", stat->proc_dir);
    remove_proc_entry(TFE_KMOD_PROC_DIR, NULL);
    kfree(stat);
}

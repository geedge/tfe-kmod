#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/net.h>

struct tfe_kmod_stat;
struct tfe_kmod_stat * tfe_kmod_stat_create(struct net * netspace);
void tfe_kmod_stat_destroy(struct tfe_kmod_stat * stat);

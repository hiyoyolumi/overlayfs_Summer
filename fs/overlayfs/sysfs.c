#include <linux/kobject.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/namei.h>

#include "ovl_entry.h"



#define BUFFER_MAX 512

typedef enum {
    attr_upper, 
    attr_lower, 
    attr_work, 
    attr_merge, 
} attr_id_t;

struct ovl_attr {
    struct attribute attr;
    short attr_id;
};

#define OVL_ATTR(_name, _mode)             \
static struct ovl_attr ovl_attr_##_name = {     \
    .attr = {.name = __stringify(_name), .mode = _mode},    \
    .attr_id = attr_##_name, \
}

#define ATTR_LIST(name) &ovl_attr_##name.attr

struct kobject *ovl_root;


OVL_ATTR(upper, 0444);
OVL_ATTR(lower, 0444);
OVL_ATTR(work, 0444);
OVL_ATTR(merge, 0444);
static struct attribute *default_attrs[] = {
    ATTR_LIST(upper),
    ATTR_LIST(lower),
    ATTR_LIST(work),
    ATTR_LIST(merge),
    NULL
};

static int get_merge_name(const char *dir, char *buf, int len)
{
    char* const delim = "/";
    char *token, *cur;
    char *tmp;

    tmp = kstrdup(dir, GFP_KERNEL);
    if (!tmp)
        return -ENOMEM;
    
    cur = tmp;
    while (token = strsep(&cur, delim)) {
        snprintf(buf, len, "%s", token);
    }
    
    kfree(tmp);
    return 0;
}

/* back up the mergedir and rename kobject */
int ovl_mergedir_backup_kobj_rename(struct super_block *sb, const char *str)
{
    struct ovl_fs *ofs = sb->s_fs_info;
    char new_name[128];
    unsigned seq;
    int err;

    write_seqlock(&ofs->config_backup.config_sl);
    ofs->config_backup.mergedir = kstrdup(str, GFP_KERNEL);
    write_sequnlock(&ofs->config_backup.config_sl);
    if (!ofs->config_backup.mergedir)
        return -ENOMEM;
    
    do {
        seq = read_seqbegin(&ofs->config_backup.config_sl);
        
        err = get_merge_name(ofs->config_backup.mergedir, 
                                new_name, sizeof(new_name));
        if (err)
            return err;
        
        snprintf(new_name, sizeof(new_name), "%s_%d_%d", new_name, 
                                MAJOR(sb->s_dev), MINOR(sb->s_dev));
        err = kobject_rename(&ofs->kobj, new_name);
        if (err)
            return err;
    } while(read_seqretry(&ofs->config_backup.config_sl, seq));

    return 0;
}

int ovl_config_backup(struct ovl_fs *ofs)
{
    write_seqlock(&ofs->config_backup.config_sl);
    ofs->config_backup.upperdir = kstrdup(ofs->config.upperdir, GFP_KERNEL);
    ofs->config_backup.lowerdir = kstrdup(ofs->config.lowerdir, GFP_KERNEL);
    ofs->config_backup.workdir = kstrdup(ofs->config.workdir, GFP_KERNEL);
    write_sequnlock(&ofs->config_backup.config_sl);
    if (!ofs->config_backup.upperdir || !ofs->config_backup.lowerdir || 
                                        !ofs->config_backup.workdir)
        return -ENOMEM;
    return 0;
}

static int sl_show(struct ovl_fs *ofs, attr_id_t id, char *buf)
{
    int ret = 0;
    unsigned seq;

    switch(id)
    {
    case attr_upper:
        do {
            seq = read_seqbegin(&ofs->config_backup.config_sl);
            ret = snprintf(buf, PAGE_SIZE, "%s\n", ofs->config_backup.upperdir);
        } while(read_seqretry(&ofs->config_backup.config_sl, seq));
        break;
    case attr_lower:
        do {
            seq = read_seqbegin(&ofs->config_backup.config_sl);
            ret = snprintf(buf, PAGE_SIZE, "%s\n", ofs->config_backup.lowerdir);
        } while(read_seqretry(&ofs->config_backup.config_sl, seq));
        break;
    case attr_work:
        do {
            seq = read_seqbegin(&ofs->config_backup.config_sl);
            ret = snprintf(buf, PAGE_SIZE, "%s\n", ofs->config_backup.workdir);
        } while(read_seqretry(&ofs->config_backup.config_sl, seq));
        break;
    case attr_merge:
        do {
            seq = read_seqbegin(&ofs->config_backup.config_sl);
            ret = snprintf(buf, PAGE_SIZE, "%s\n", ofs->config_backup.mergedir);
        } while(read_seqretry(&ofs->config_backup.config_sl, seq));
        break;
    default:
        ret = -1;
    }
    return ret;
}

ssize_t	ovl_sysfs_show(struct kobject *kobj, struct attribute *attr,
                                        char *buf)
{
    struct ovl_fs *ofs = container_of(kobj, struct ovl_fs, kobj);
    struct ovl_attr *ovl_attribute = container_of(attr, 
                    struct ovl_attr, attr);
    attr_id_t id = ovl_attribute->attr_id;

    return sl_show(ofs, id, buf);
}
 
ssize_t	ovl_sysfs_store(struct kobject *kobj, struct attribute *attr, 
                                        const char *buf, size_t size)
{
    return 0;
}

void free_path(struct ovl_fs *ofs)
{
    kfree(ofs->config_backup.upperdir);
    kfree(ofs->config_backup.lowerdir);
    kfree(ofs->config_backup.workdir);
    kfree(ofs->config_backup.mergedir);
}

void ovl_kobj_release(struct kobject *kobj)
{
    struct ovl_fs *ofs = container_of(kobj, struct ovl_fs, kobj);

    free_path(ofs);
}
 
struct sysfs_ops ovl_sysfs_ops = {
    .show = ovl_sysfs_show,
    .store = ovl_sysfs_store
};

struct kobj_type ovl_sb_ktype = {
    .release = ovl_kobj_release,
    .sysfs_ops = &ovl_sysfs_ops,
    .default_attrs = default_attrs
};

#define TMP_LEN 512
static int get_mount_path_to_ofs(struct ovl_fs *ofs)
{
    struct path temp_path = { };
    char buf[TMP_LEN];
    char *str;
    int err = 0;

    /* Only sed to segmentation the lower dirs */
    char* const delim = ":";
    char *lower_str = NULL, *lower_tmp = NULL;
    char *token, *cur;
    int alloc_len = TMP_LEN;    /* lower_tmp's capacity */
    int tmp_len;

    /* get upper dir */
    err = kern_path(ofs->config.upperdir, LOOKUP_FOLLOW, &temp_path);
    if (err) {
        pr_err("overlayfs: failed to resolve '%s': %i\n", 
                        ofs->config.upperdir, err);
        return err;
    }
    str = d_path(&temp_path, buf, TMP_LEN);
    kfree(ofs->config.upperdir);
    ofs->config.upperdir = kstrdup(str, GFP_KERNEL);
    if (!ofs->config.upperdir)
        return -ENOMEM;

    /* deal with lower dirs */
    lower_str = kstrdup(ofs->config.lowerdir, GFP_KERNEL);
    if (!lower_str)
        goto out_free;
    cur = lower_str;
    lower_tmp = kzalloc(alloc_len, GFP_KERNEL);
    if (!lower_tmp)
        goto out_free;
    while (token = strsep(&cur, delim)) {
        err = kern_path(token, LOOKUP_FOLLOW, &temp_path);
        if (err) {
            pr_err("overlayfs: failed to resolve '%s': %i\n", 
                        ofs->config.upperdir, err);
            return err;
        }
        str = d_path(&temp_path, buf, TMP_LEN);

        tmp_len = strlen(str);
        if (alloc_len <= tmp_len) {
            tmp_len += strlen(lower_tmp);
            lower_tmp = krealloc(lower_tmp, tmp_len, GFP_KERNEL);
            if (!lower_tmp)
                goto out_free;
            alloc_len += tmp_len;
        }
        if (!(*lower_tmp))
            snprintf(lower_tmp, alloc_len, "%s", str);
        else 
            snprintf(lower_tmp, alloc_len, "%s\n%s", lower_tmp, str);
        alloc_len -= strlen(str);
    }
    kfree(ofs->config.lowerdir);
    ofs->config.lowerdir = kstrdup(lower_tmp, GFP_KERNEL);
    kfree(lower_str);
    kfree(lower_tmp);
    if(!ofs->config.lowerdir)
        goto out_free;

    /* get work dir */
    err = kern_path(ofs->config.workdir, LOOKUP_FOLLOW, &temp_path);
    if (err) {
        pr_err("overlayfs: failed to resolve '%s': %i\n", 
                        ofs->config.workdir, err);
        return err;
    }
    str = d_path(&temp_path, buf, TMP_LEN);
    kfree(ofs->config.workdir);
    ofs->config.workdir = kstrdup(str, GFP_KERNEL);
    if (!ofs->config.workdir)
        goto out_free;
    
    return 0;

out_free:
    if (lower_tmp)
        kfree(lower_tmp);
    if (lower_str)
        kfree(lower_str);
    return -ENOMEM;
}
#undef TMP_LEN

int ovl_register_sysfs(struct super_block *sb)
{
    struct ovl_fs *ofs = OVL_FS(sb);
    int err = 0;

    err = get_mount_path_to_ofs(ofs);
    if (err)
        return err;

    err = kobject_init_and_add(&ofs->kobj, &ovl_sb_ktype, ovl_root, 
                    "merge_%d_%d", MAJOR(sb->s_dev), MINOR(sb->s_dev));
    if (err) {
        kobject_put(&ofs->kobj);
        return err;
    }

    err = ovl_config_backup(ofs);
    if (err)
        return err;

    return 0;
}



MODULE_LICENSE("GPL");
static int __init ovl_kobject_init(void)
{
    /* create the /sys/fs/overlayfs directory */
    ovl_root = kobject_create_and_add("overlayfs", fs_kobj);
    if (!ovl_root)
		return -ENOMEM;
    return 0;
}

static void __exit ovl_kobject_exit(void)
{
    kobject_put(ovl_root);
    ovl_root = NULL;
}
module_init(ovl_kobject_init);
module_exit(ovl_kobject_exit);
MODULE_AUTHOR("hiixfj");
MODULE_DESCRIPTION("overlayfs_sysfs_register");

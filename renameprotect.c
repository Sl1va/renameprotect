/*
 * wmtd-rw - Make specified list of MTD partitions writeable
 *
 * Copyright (C), 2025, Emil Latypov <emillatypov9335@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 *
 * Usage:
 *   TBD
 */

#include <linux/dcache.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/string.h>

#ifndef MODULE
#error "Must be compiled as a module."
#endif

#define MOD_LOG "renameprotect: "
#define MOD_WARNING KERN_WARNING MOD_LOG
#define MOD_INFO KERN_INFO MOD_LOG
#define MOD_ERR KERN_ERR MOD_LOG

#define FILTER_EXTENSION ".txt"
#define FILTER_LEN strlen(FILTER_EXTENSION)

static char *prothead = "";
module_param(prothead, charp, S_IRUGO);
MODULE_PARM_DESC(
    prothead,
    "16-bytes header to activate rename protection at all *.txt files");

static int vfs_rename_handler(struct kprobe *p, struct pt_regs *regs);

static struct kprobe kp_rename = {.symbol_name = "vfs_rename",
                                  .pre_handler = vfs_rename_handler};

static int vfs_rename_handler(struct kprobe *p, struct pt_regs *regs) {
    /*
    The vfs_rename function prototype is following:

    int vfs_rename(struct inode * old_dir,
                    struct dentry * old_dentry,
                    struct inode * new_dir,
                    struct dentry * new_dentry,
                    struct inode ** delegated_inode,
                    unsigned int flags);

    So, in order to address specified arguments, they can be
    accessed via their order (see regs_get_kernel_argument)
    */

    struct dentry *old_dentry =
        (struct dentry *)regs_get_kernel_argument(regs, 1);

    u32 oldlen = old_dentry->d_name.len;
    const char *oldname = old_dentry->d_name.name;

    if (oldlen < FILTER_LEN) {
        return 0;
    }

    if (!memcmp(oldname + oldlen - FILTER_LEN, FILTER_EXTENSION, FILTER_LEN)) {
        printk(MOD_INFO "%s rename were rejected\n", oldname);

        // Make vfs_rename think that source filename
        // has zero lengths, so it will lead to operation
        // fail automatically
        old_dentry->d_name.len = 0;
    }

    return 0;
}

/**
 * @brief Kernel module initialization
 *
 * @return int Non-zero error value on failure, otherwise 0
 */
static int __init renameprotect_init(void) {
    int retcode = register_kprobe(&kp_rename);
    if (retcode == 0) {
        printk(MOD_ERR "Registered hook for %s\n", kp_rename.symbol_name);
    } else {
        printk(MOD_ERR "Failed to register hook for %s (%d)\n",
               kp_rename.symbol_name, retcode);
        return retcode;
    }

    return 0;
}

/**
 * @brief Kernel module deinitialization
 */
static void __exit renameprotect_exit(void) { unregister_kprobe(&kp_rename); }

module_init(renameprotect_init);
module_exit(renameprotect_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Emil Latypov <emillatypov9335@gmail.com>");
MODULE_DESCRIPTION("TBD");
MODULE_VERSION("1");

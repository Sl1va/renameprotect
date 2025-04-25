/*
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
 *   sudo insmod renameprotect.ko prothead="aaaabbbbccccdddd"
 * where prothread is 16-byte header to check on *.txt files before renaming
 * (if the header mathces, rename operation will be rejected)
 */

#include <linux/dcache.h>
#include <linux/fs_struct.h>
#include <linux/highmem.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>

#ifndef MODULE
#error "Must be compiled as a module."
#endif

#define MOD_LOG "renameprotect: "
#define MOD_WARNING KERN_WARNING MOD_LOG
#define MOD_INFO KERN_INFO MOD_LOG
#define MOD_ERR KERN_ERR MOD_LOG

#define FILTER_EXTENSION ".txt"
#define FILTER_EXT_LEN strlen(FILTER_EXTENSION)
#define FILTER_HEADER_LEN 16

static char *prothead = "";
module_param(prothead, charp, S_IRUGO);
MODULE_PARM_DESC(
    prothead,
    "16-bytes header to activate rename protection at all *.txt files");

static int vfs_rename_handler(struct kprobe *p, struct pt_regs *regs);

static struct kprobe kp_rename = {.symbol_name = "vfs_rename",
                                  .pre_handler = vfs_rename_handler};

static ssize_t read_header(struct dentry *dentry, u8 *header) {
    struct path root;
    struct file *filerd;
    ssize_t bytes_read;
    mm_segment_t old_fs;

    task_lock(&init_task);
    get_fs_root(init_task.fs, &root);
    task_unlock(&init_task);

    root.dentry = dentry;

    filerd = file_open_root(root.dentry->d_parent, root.mnt,
                            root.dentry->d_name.name, O_RDONLY, 0);

    old_fs = get_fs();  // Save the current address limit
    set_fs(KERNEL_DS);  // Set the address limit to kernel space

    bytes_read = kernel_read(filerd, header, FILTER_HEADER_LEN, NULL);
    filp_close(filerd, NULL);
    set_fs(old_fs);

    return bytes_read;
}

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

    struct dentry *dentry = (struct dentry *)regs_get_kernel_argument(regs, 1);

    u32 oldlen = dentry->d_name.len;
    const char *oldname = dentry->d_name.name;

    if (oldlen < FILTER_EXT_LEN) {
        return 0;
    }

    if (!memcmp(oldname + oldlen - FILTER_EXT_LEN, FILTER_EXTENSION,
                FILTER_EXT_LEN)) {
        u8 header[FILTER_HEADER_LEN] = {0};
        ssize_t bytes_read = read_header(dentry, header);

        if (bytes_read == sizeof(header) &&
            !memcmp(prothead, header, bytes_read)) {
            // Make vfs_rename think that source filename
            // has zero lengths, so it will lead to operation
            // fail automatically
            dentry->d_name.len = 0;
            printk(MOD_INFO "%s rename were rejected\n", oldname);
        }
    }

    return 0;
}

/**
 * @brief Kernel module initialization
 *
 * @return int Non-zero error value on failure, otherwise 0
 */
static int __init renameprotect_init(void) {
    int retcode;
    unsigned long header_len;

    header_len = strlen(prothead);
    if (header_len != FILTER_HEADER_LEN) {
        printk(MOD_ERR "Invalid prothead size. Expected %u, got %lu\n",
               FILTER_HEADER_LEN, header_len);
        return -EINVAL;
    }

    retcode = register_kprobe(&kp_rename);
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
MODULE_DESCRIPTION("Rename protection for *.txt files with specified header");
MODULE_VERSION("1");

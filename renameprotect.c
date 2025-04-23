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

#include <asm/unistd.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>

#ifndef MODULE
#error "Must be compiled as a module."
#endif

#define MOD_LOG "renameprotect: "
#define MOD_WARNING KERN_WARNING MOD_LOG
#define MOD_INFO KERN_INFO MOD_LOG
#define MOD_ERR KERN_ERR MOD_LOG

static char *prothead = "";
module_param(prothead, charp, S_IRUGO);
MODULE_PARM_DESC(
    prothead,
    "16-bytes header to activate rename protection at all *.txt files");

static void **sys_call_table;

asmlinkage long (*orig_sys_rename)(const char __user *, const char __user *);
asmlinkage long fake_sys_rename(const char __user *oldname,
                                const char __user *newname) {
    printk(MOD_ERR "Oh shit it works (%s)\n", __func__);
    return orig_sys_rename(oldname, newname);
}

asmlinkage long (*orig_sys_renameat)(int, const char __user *, int,
                                     const char __user *);
asmlinkage long fake_sys_renameat(int olddfd, const char __user *oldname,
                                  int newdfd, const char __user *newname) {
    printk(MOD_ERR "Oh shit it works (%s)\n", __func__);
    return orig_sys_renameat(olddfd, oldname, newdfd, newname);
}

asmlinkage long (*orig_sys_renameat2)(int, const char __user *, int,
                                      const char __user *, unsigned int);
asmlinkage long fake_sys_renameat2(int olddfd, const char __user *oldname,
                                   int newdfd, const char __user *newname,
                                   unsigned int flags) {
    printk(MOD_ERR "Oh shit it works (%s)\n", __func__);
    return orig_sys_renameat2(olddfd, oldname, newdfd, newname, flags);
}

/**
 * @brief Kernel module initialization
 *
 * @return int Non-zero error value on failure, otherwise 0
 */
static int __init renameprotect_init(void) {
    sys_call_table = (void *)kallsyms_lookup_name("sys_call_table");

    if (!sys_call_table) {
        printk(MOD_ERR "Failed to find sys_call_table\n");
        return -EINVAL;
    } else {
        printk(MOD_ERR "sys_call_table was successfully found\n");
    }

    orig_sys_rename = sys_call_table[__NR_rename];
    orig_sys_renameat = sys_call_table[__NR_renameat];
    orig_sys_renameat2 = sys_call_table[__NR_renameat2];

    sys_call_table[__NR_rename] = fake_sys_rename;
    sys_call_table[__NR_renameat] = fake_sys_renameat;
    sys_call_table[__NR_renameat2] = fake_sys_renameat2;

    return 0;
}

/**
 * @brief Kernel module deinitialization
 */
static void __exit renameprotect_exit(void) {
    sys_call_table[__NR_rename] = orig_sys_rename;
    sys_call_table[__NR_renameat] = orig_sys_renameat;
    sys_call_table[__NR_renameat2] = orig_sys_renameat2;
}

module_init(renameprotect_init);
module_exit(renameprotect_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Emil Latypov <emillatypov9335@gmail.com>");
MODULE_DESCRIPTION("TBD");
MODULE_VERSION("1");

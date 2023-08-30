#!/usr/bin/env python3

# Heavily adapted from
# This uses in-kernel eBPF maps to store per process summaries for efficiency.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 06-Feb-2016   Brendan Gregg   Created this.
# July 2023 Richard Clegg made some hackish modifications adding no real value

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime

from subprocess import call


warnings= ['Do not look at the file', 'I asked you not to look at the file', 
'When will you learn not to look at the file', 'Really do not look at the file', 
'This is the last time I warn you about looking at the file',
'OK THIS is the last time I warn you about looking at the file',
'I warned you']
def alert(wcount):
    print(warnings[wcount])
    return wcount >= len(warnings)-1


# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

// the key for the output summary
struct info_t {
    u32 name_len;
    char name[DNAME_INLINE_LEN];
};



BPF_HASH(access, struct info_t, int);

int trace_read_entry(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count)
{
    int bodge=1;

    // skip I/O lacking a filename
    struct dentry *de = file->f_path.dentry;
    int mode = file->f_inode->i_mode;
    struct qstr d_name = de->d_name;
    if (d_name.len == 0)
        return 0;

    // store info we need
    struct info_t info = {
        .name_len= d_name.len
    };
    bpf_probe_read_kernel(&info.name, sizeof(info.name), d_name.name);

    access.lookup_or_try_init(&info, &bodge);

    return 0;
}




"""


# initialize BPF
b = BPF(text=bpf_text, cflags=["-Wno-macro-redefined"])
b.attach_kprobe(event="vfs_read", fn_name="trace_read_entry")

print('I am watching you... Hit Ctrl-C to end')

exiting = False
times=0
while True:
    try:
        sleep(1)
    except KeyboardInterrupt:
        exiting = True

    access = b.get_table("access")
    for k, v in access.items():
        if k.name == bytes("handsoff.txt", 'utf-8'):
            if alert(times):
                exiting= True
            times+=1
    access.clear()

    if exiting:
        print("I know when I am not wanted.")
        exit()

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
import ctypes



# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

// the key for the output summary
struct info_t {
    u64 fib;
    u32 name_len;
    char name[DNAME_INLINE_LEN];
    
};

static u64 fib(n)
{
  u64 first=0, second=1, result;
  int i= 2;
  while (1)
  {
      result = first + second;
      first = second;
      second = result;
      i++;
      if (i > n)
        return result;
  } 
  return result;
}

BPF_HASH(access, struct info_t, int);

int trace_read_entry(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count)
{
    u32 bodge=1;

    // skip I/O lacking a filename
    struct dentry *de = file->f_path.dentry;
    int mode = file->f_inode->i_mode;
    struct qstr d_name = de->d_name;
    if (d_name.len == 0)
        return 0;

    struct info_t info = {
        .name_len= d_name.len,
        .fib= fib(40)
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
    for k,v in access.items():
        if k.name == bytes("handsoff.txt", 'utf-8'):
            print("The fibonnaci number is", k.fib)
            times+=1
    access.clear()

    if exiting:
        print("I know when I am not wanted.")
        exit()

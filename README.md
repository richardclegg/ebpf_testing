These are very basic demo files to investigate eBPF at an extremely simple level.

A good way to start (far better than this trivial intro) is the lab here: ']

https://play.instruqt.com/embed/isovalent/tracks/ebpf-getting-started?token=em_9nxLzhlV41gb3rKM&show_challenges=true

or the resources here

https://www.brendangregg.com/blog/2019-01-01/learn-ebpf-tracing.html

In recent versions of Ubuntu at least package names and command names have been changing around. I suspect this information will be very different for very different releases of Ubuntu (never mind different distros). In Ubuntu 22.04 I needed

```
# sudo apt install bpfcc-tools 
# sudo apt install linux-tools-generic
# sudo apt install linux-hwe-6.2-tools-common
# sudo apt install libbpf-dev
```

Also for some reason opensnoop (referred to by a lot of tutorials) is known as opensnoop-bpfcc. 

I found it useful to clone:
git@github.com:iovisor/bcc.git
To get example code to look at.

Also note that on Ubuntu 22.04 programs like opensnoop-bpfcc give a warning (yet still run). 
https://github.com/iovisor/bcc/issues/3366








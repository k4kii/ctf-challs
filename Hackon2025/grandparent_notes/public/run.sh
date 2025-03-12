#!/usr/bin/env bash

qemu-system-x86_64 \
    -m 128M \
    -cpu qemu64-v1,+smap,+smep \
    -smp cores=2,threads=2 \
    -kernel ./bzImage \
    -initrd ./rootfs.cpio.gz \
    -nographic \
    -monitor /dev/null \
    -append "console=ttyS0 kaslr pti=on quiet oops=panic panic=1 init=/init" \
    -no-reboot \
    -snapshot

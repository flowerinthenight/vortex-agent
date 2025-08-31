#!/bin/sh

# Run by `//go generate` in main.go.
env bpf2go \
    -target amd64 \
    -tags linux \
    -cflags "-O2 -g -Wall -Werror -Wno-unused-but-set-variable" \
    -type event \
    -output-dir bpf/ \
    -go-package bpf \
    Bpf ./bpf/vortex.c \
    -- \
    -I./libbpf/src \
    -I./vmlinux.h/include/x86_64 \
    ${EXTRA_BPF2GO_CFLAGS:=-DDEBUG_BPF_PRINTK=1}

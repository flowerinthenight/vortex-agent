[![main](https://github.com/flowerinthenight/vortex-agent/actions/workflows/main.yml/badge.svg)](https://github.com/flowerinthenight/vortex-agent/actions/workflows/main.yml)

> [!CAUTION]
> Alpha-level software; requires root access. Use with caution.

## Setup

```sh
# If first clone:
$ git clone --recurse-submodules https://github.com/flowerinthenight/vortex-agent

# Note only; we use the vmlinux.h submodule instead of the generated header.
# $ bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Only needed when C file(s) are updated:
$ go generate

# Normal builds:
$ make

# Run:
$ [sudo] ./bin/vortex-agent run --logtostderr

# To be able to list pods (if deployed to k8s):
$ kubectl create clusterrolebinding default-view \
  --clusterrole=view \
  --serviceaccount=default:default

# Deploy to k8s as daemonset:
$ kubectl create -f daemonset.yaml
```

## Testing

If possible, test using k8s, or cloud VMs. But to test for specific kernel versions, however, below is a rough guide on how to setup a specific kernel version with a Debian system using [QEMU](https://www.qemu.org/).

```sh
# Install prerequisites:
$ sudo apt update
$ sudo apt git install make gcc flex bison libncurses-dev libelf-dev libssl-dev \
      debootstrap dwarves qemu-system -y

# Clone stable Linux kernel:
$ cd $WORKDIR/
$ git clone git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git

# Checkout desired version (tag):
$ cd linux-stable/
$ git checkout -b v6.6.102 v6.6.102

# Configure kernel build:
$ $VORTEX_AGENT_ROOT/tools/config-kernel.sh
$ make -j$(nproc)

# Create a Debian Bullseye Linux image:
$ cd ../
$ mkdir -p debian-bullseye/
$ cd debian-bullseye/
$ wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh
$ chmod +x create-image.sh
$ ./create-image.sh --feature full

# Run the image:
$ cd ../
$ qemu-system-x86_64 \
      -m 2G \
      -smp 2 \
      -kernel linux-stable/arch/x86/boot/bzImage \
      -append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0" \
      -drive file=debian-bullseye/bullseye.img,format=raw \
      -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
      -net nic,model=e1000 \
      -enable-kvm \
      -nographic \
      -pidfile vm.pid \
      2>&1 | tee vm.log

# On another terminal, you can use scp and ssh.
# Copy vortex-agent binary to the VM using scp:
$ scp -i debian-bullseye/bullseye.id_rsa -P 10021 \
      -o "StrictHostKeyChecking no" \
      $VORTEX_AGENT_ROOT/bin/vortex-agent \
      root@localhost:~/

# ssh to the VM using the forwarded port:
$ ssh -i debian-bullseye/bullseye.id_rsa -p 10021 \
      -o "StrictHostKeyChecking no" root@localhost

# and run the binary:
$ ./vortex-agent run --logtostderr

# You can close the VM by running (within the VM):
$ poweroff

# or from outside the VM:
$ kill [-9] $(cat vm.pid)
```

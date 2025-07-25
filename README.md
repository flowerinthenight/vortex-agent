```sh
# If first clone:
$ git clone --recurse-submodules https://github.com/flowerinthenight/vortex-agent

# Note only; we use the vmlinux.h submodule instead of the generated header.
$ bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Only needed when C file(s) are updated:
$ go generate

# Normal builds:
$ make

# Run:
$ [sudo] ./bin/vortex-agent -logtostderr

# To be able to list pods:
$ kubectl create clusterrolebinding default-view \
  --clusterrole=view \
  --serviceaccount=default:default

# Deploy to k8s as daemonset:
$ kubectl create -f daemonset.yaml
```

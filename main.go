//go:build linux

//go:generate sh bpf2go.sh

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"maps"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/flowerinthenight/vortex-agent/bpf"
	"github.com/flowerinthenight/vortex-agent/internal"
	"github.com/golang/glog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	testf = flag.Bool("test", false, "Run in test mode")
)

type trafficInfo struct {
	ExtraInfo string
	Ingress   uint64 // bytes received
	Egress    uint64 // bytes sent
}

func main() {
	flag.Parse()
	defer glog.Flush()

	if *testf {
		test()
		return
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	podUids := make(map[string]string) // key: pod-uid, value: ns/pod-name
	podUidsMtx := sync.Mutex{}

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		glog.Errorf("RemoveMemlock failed: %v", err)
		return
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpf.BpfObjects{}
	if err := bpf.LoadBpfObjects(&objs, nil); err != nil {
		glog.Errorf("loadBpfObjects failed: %v", err)
		return
	}

	defer objs.Close()
	glog.Info("BPF objects loaded successfully")

	ssm, err := link.AttachTracing(link.TracingOptions{
		Program:    objs.SockSendmsgFentry,
		AttachType: ebpf.AttachTraceFEntry,
	})

	if err != nil {
		glog.Errorf("fentry/sock_sendmsg failed: %v", err)
		return
	}

	defer ssm.Close()
	glog.Info("fentry/sock_sendmsg attached successfully")

	srm, err := link.AttachTracing(link.TracingOptions{
		Program:    objs.SockRecvmsgFexit,
		AttachType: ebpf.AttachTraceFExit,
	})

	if err != nil {
		glog.Errorf("fexit/sock_recvmsg failed: %v", err)
		return
	}

	defer srm.Close()
	glog.Info("fexit/sock_recvmsg attached successfully")

	tsm, err := link.AttachTracing(link.TracingOptions{
		Program:    objs.TcpSendmsgFexit,
		AttachType: ebpf.AttachTraceFExit,
	})

	if err != nil {
		glog.Errorf("fexit/tcp_sendmsg failed: %v", err)
		return
	}

	defer tsm.Close()
	glog.Info("fexit/tcp_sendmsg attached successfully")

	usm, err := link.AttachTracing(link.TracingOptions{
		Program:    objs.UdpSendmsgFexit,
		AttachType: ebpf.AttachTraceFExit,
	})

	if err != nil {
		glog.Errorf("fexit/udp_sendmsg failed: %v", err)
		return
	}

	defer usm.Close()
	glog.Info("fexit/udp_sendmsg attached successfully")

	// kssm, err := link.Kprobe("sock_sendmsg", objs.SockSendmsgEntry, nil)
	// if err != nil {
	// 	slog.Error("kprobe/sock_sendmsg failed:", "err", err)
	// 	return
	// }

	// defer kssm.Close()
	// slog.Info("kprobe/sock_sendmsg attached successfully")

	// tpsnst, err := link.Tracepoint("syscalls", "sys_enter_sendto", objs.HandleEnterSendto, nil)
	// if err != nil {
	// 	slog.Error("tracepoint/syscalls/sys_enter_sendto failed:", "err", err)
	// 	return
	// }

	// defer tpsnst.Close()
	// slog.Info("tracepoint/syscalls/sys_enter_sendto attached successfully")

	libsslPath, err := findLibSSL()
	if err != nil {
		glog.Errorf("Error finding libssl.so: %v", err)
		return
	}

	if libsslPath != "" {
		ex, err := link.OpenExecutable(libsslPath)
		if err != nil {
			glog.Errorf("OpenExecutable failed: %v", err)
			return
		}

		upSSLWrite, err := ex.Uprobe("SSL_write", objs.UprobeSSL_write, nil)
		if err != nil {
			glog.Errorf("Uprobe (uprobe/SSL_write) failed: %v", err)
			return
		}

		defer upSSLWrite.Close()
		glog.Info("uprobe/SSL_write attached successfully")

		urpSSLWrite, err := ex.Uretprobe("SSL_write", objs.UretprobeSSL_write, nil)
		if err != nil {
			glog.Errorf("Uretprobe (uretprobe/SSL_write) failed: %v", err)
			return
		}

		defer urpSSLWrite.Close()
		glog.Info("uretprobe/SSL_write attached successfully")

		upSSLRead, err := ex.Uprobe("SSL_read", objs.UprobeSSL_read, nil)
		if err != nil {
			glog.Errorf("Uprobe (uprobe/SSL_read) failed: %v", err)
			return
		}

		defer upSSLRead.Close()
		glog.Info("uprobe/SSL_read attached successfully")

		urpSSLRead, err := ex.Uretprobe("SSL_read", objs.UretprobeSSL_read, nil)
		if err != nil {
			glog.Errorf("Uretprobe (uretprobe/SSL_read) failed: %v", err)
			return
		}

		defer urpSSLRead.Close()
		glog.Info("uretprobe/SSL_read attached successfully")
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		glog.Errorf("ringbuf reader failed: %v", err)
		return
	}

	defer rd.Close()

	go func() {
		<-stopper

		if err := rd.Close(); err != nil {
			glog.Errorf("rd.Close failed: %v", err)
			os.Exit(1)
		}
	}()

	go func() {
		config, err := rest.InClusterConfig()
		if err != nil {
			glog.Errorf("InClusterConfig failed: %v", err)
			return
		}

		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			glog.Errorf("NewForConfig failed: %v", err)
			return
		}

		for {
			// Can also remove the namespace argument to list all namespaces.
			pods, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
			if err != nil {
				glog.Errorf("List pods failed: %v", err)
				return
			}

			for _, pod := range pods.Items {
				if pod.Namespace == "kube-system" {
					continue // skip kube-system namespace
				}

				// glog.Infof("pod=%s, ns=%s, uid=%s", pod.Name, pod.Namespace, string(pod.ObjectMeta.UID))

				podUidsMtx.Lock()
				podUids[string(pod.ObjectMeta.UID)] = fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
				podUidsMtx.Unlock()
			}

			time.Sleep(10 * time.Second)
		}
	}()

	tracedTgids := make(map[uint32]*trafficInfo) // key: tgid
	tracedTgidsMtx := sync.Mutex{}

	go func(hm *ebpf.Map) {
		rootPidNsId := internal.GetInitPidNsId()
		if rootPidNsId == -1 {
			glog.Error("invalid init PID namespace")
			return
		}

		for {
			files, err := os.ReadDir("/proc")
			if err != nil {
				glog.Errorf("ReadDir /proc failed: %v", err)
				return
			}

			for _, f := range files {
				pid, err := strconv.Atoi(f.Name())
				if err != nil {
					continue
				}

				nspidLink, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid))
				if err != nil {
					continue
				}

				// Format "pid:[<num>]"
				parts := strings.Split(nspidLink, ":")
				if len(parts) < 2 {
					continue
				}

				nspid, err := strconv.Atoi(parts[1][1 : len(parts[1])-1])
				if err != nil {
					continue
				}

				if nspid == rootPidNsId {
					continue // assumed not a container process (host process)
				}

				cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
				if err != nil {
					glog.Errorf("ReadFile failed: %v", err)
					return
				}

				args := bytes.Split(cmdline, []byte{0x00})
				var fargs []string
				for _, arg := range args {
					s := string(arg)
					if s != "" {
						fargs = append(fargs, s)
					}
				}

				fullCmdline := strings.Join(fargs, " ")
				// glog.Infof("jailed: pid=%d, cmdline=%s", pid, strings.Join(fargs, " "))

				if strings.HasPrefix(fullCmdline, "/pause") {
					continue // skip pause binaries
				}

				cgroupb, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
				if err != nil {
					glog.Errorf("ReadFile failed: %v", err)
					return
				}

				cgroup := string(cgroupb)
				// glog.Infof("jailed: pid=%d, cgroup=%s", pid, cgroup)

				podUidsMtx.Lock()
				clone := make(map[string]string, len(podUids))
				maps.Copy(clone, podUids)
				podUidsMtx.Unlock()

				for k, v := range clone {
					// NOTE: This is a very fragile way of matching cgroup to pod. Tested only on GKE (Alphaus).
					// Need to explore other k8s setups, i.e. EKS, AKS, OpenShift, etc.
					kf := strings.ReplaceAll(k, "-", "_")
					if strings.Contains(cgroup, kf) {
						// glog.Infof("found pod: pid=%d, ns/pod=%s, cmdline=%v", pid, v, strings.Join(fargs, " "))

						tgid := uint32(pid)
						err = hm.Put(uint32(tgid), []byte{1}) // mark as traced
						if err != nil {
							glog.Errorf("hm.Put failed: %v", err)
						} else {
							val := fmt.Sprintf("%s/%s", v, fullCmdline)
							tracedTgidsMtx.Lock()
							if _, ok := tracedTgids[tgid]; !ok {
								tracedTgids[tgid] = &trafficInfo{ExtraInfo: val}
							}

							tracedTgidsMtx.Unlock()
							// glog.Infof("added to tracedTgids: tgid=%d, val=%s", tgid, val)
						}
					}
				}
			}

			time.Sleep(10 * time.Second)
		}
	}(objs.TgidsToTrace)

	go func() {
		for {
			tracedTgidsMtx.Lock()
			clone := make(map[uint32]*trafficInfo, len(tracedTgids))
			maps.Copy(clone, tracedTgids)
			tracedTgidsMtx.Unlock()

			limit := 100
			for tgid, ei := range clone {
				var info string
				if len(ei.ExtraInfo) <= limit {
					info = ei.ExtraInfo
				} else {
					info = ei.ExtraInfo[:limit] + "..."
				}

				ingress := atomic.LoadUint64(&ei.Ingress)
				egress := atomic.LoadUint64(&ei.Egress)
				if (ingress + egress) == 0 {
					continue // skip if no traffic
				}

				glog.Infof("traced tgid=%09d, info=%s, ingress=%d, egress=%d",
					tgid,
					info,
					ingress,
					egress,
				)
			}

			time.Sleep(10 * time.Second)
		}
	}()

	// var count uint64
	var line strings.Builder
	var event bpf.BpfEvent

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				glog.Info("received signal, exiting...")
				return
			}

			glog.Errorf("reading from reader failed: %v", err)
			continue
		}

		// count++
		// if count%1000 == 0 {
		// 	glog.Infof("count: %d", count)
		// }

		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			glog.Errorf("parsing ringbuf event failed: %v", err)
			continue
		}

		line.Reset()

		switch event.Type {
		case 9:
			fmt.Fprintf(&line, "buf=%s, pid=%v, tgid=%v, ret=%v, fn=uretprobe/SSL_read",
				event.Comm,
				event.Pid,
				event.Tgid,
				event.Bytes,
			)

			glog.Info(line.String())
		case 8:
			fmt.Fprintf(&line, "buf=%s, pid=%v, tgid=%v, ret=%v, fn=uprobe/SSL_read",
				event.Comm,
				event.Pid,
				event.Tgid,
				event.Bytes,
			)

			glog.Info(line.String())
		case 7:
			fmt.Fprintf(&line, "buf=%s, pid=%v, tgid=%v, ret=%v, fn=uretprobe/SSL_write",
				event.Comm,
				event.Pid,
				event.Tgid,
				event.Bytes,
			)

			glog.Info(line.String())
		case 6:
			fmt.Fprintf(&line, "buf=%s, pid=%v, tgid=%v, ret=%v, fn=uprobe/SSL_write",
				event.Comm,
				event.Pid,
				event.Tgid,
				event.Bytes,
			)

			glog.Info(line.String())
		case 5:
			// NOTE: Not used now.
			fmt.Fprintf(&line, "comm=%s, pid=%v, tgid=%v, ret=%v, fn=sys_enter_sendto",
				event.Comm,
				event.Pid,
				event.Tgid,
				event.Bytes,
			)

			glog.Info(line.String())
		case 4:
			// fmt.Fprintf(&line, "comm=%s, pid=%v, tgid=%v, src=%v:%v, dst=%v:%v, ret=%v, fn=fexit/udp_sendmsg",
			// 	event.Comm,
			// 	event.Pid,
			// 	event.Tgid,
			// 	intToIP(event.Saddr),
			// 	event.Sport,
			// 	intToIP(event.Daddr),
			// 	event.Dport,
			// 	event.Bytes,
			// )

			tracedTgidsMtx.Lock()
			_, exists := tracedTgids[event.Tgid]
			tracedTgidsMtx.Unlock()
			if exists {
				atomic.AddUint64(&tracedTgids[event.Tgid].Egress, uint64(event.Bytes))
			}

			// glog.Info(line.String())
		case 3:
			if strings.HasPrefix(fmt.Sprintf("%s", event.Comm), "sshd") {
				continue
			}

			// fmt.Fprintf(&line, "comm=%s, pid=%v, tgid=%v, src=%v:%v, dst=%v:%v, ret=%v, fn=fexit/tcp_sendmsg",
			// 	event.Comm,
			// 	event.Pid,
			// 	event.Tgid,
			// 	intToIP(event.Saddr),
			// 	event.Sport,
			// 	intToIP(event.Daddr),
			// 	event.Dport,
			// 	event.Bytes,
			// )

			tracedTgidsMtx.Lock()
			_, exists := tracedTgids[event.Tgid]
			tracedTgidsMtx.Unlock()
			if exists {
				atomic.AddUint64(&tracedTgids[event.Tgid].Egress, uint64(event.Bytes))
			}

			// glog.Info(line.String())
		case 2:
			// fmt.Fprintf(&line, "comm=%s, pid=%v, tgid=%v, src=%v:%v, dst=%v:%v, ret=%v, fn=fexit/sock_recvmsg",
			// 	event.Comm,
			// 	event.Pid,
			// 	event.Tgid,
			// 	intToIP(event.Daddr),
			// 	event.Dport,
			// 	intToIP(event.Saddr),
			// 	event.Sport,
			// 	event.Bytes,
			// )

			tracedTgidsMtx.Lock()
			_, exists := tracedTgids[event.Tgid]
			tracedTgidsMtx.Unlock()
			if exists {
				atomic.AddUint64(&tracedTgids[event.Tgid].Ingress, uint64(event.Bytes))
			}

			// glog.Info(line.String())
		case 1:
			// fmt.Fprintf(&line, "comm=%s, pid=%v, tgid=%v, src=%v:%v, dst=%v:%v, ret=%v, fn=fentry/sock_sendmsg",
			// 	event.Comm,
			// 	event.Pid,
			// 	event.Tgid,
			// 	intToIP(event.Saddr),
			// 	event.Sport,
			// 	intToIP(event.Daddr),
			// 	event.Dport,
			// 	event.Bytes,
			// )

			tracedTgidsMtx.Lock()
			_, exists := tracedTgids[event.Tgid]
			tracedTgidsMtx.Unlock()
			if exists {
				atomic.AddUint64(&tracedTgids[event.Tgid].Egress, uint64(event.Bytes))
			}

			// glog.Info(line.String())
		default:
		}
	}
}

// intToIP converts IPv4 number to net.IP
func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, ipNum)
	return ip
}

// findLibSSL attempts to locate libssl.so
func findLibSSL() (string, error) {
	possiblePaths := []string{
		"/lib/x86_64-linux-gnu/libssl.so.1.1",
		"/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
		"/lib/x86_64-linux-gnu/libssl.so.3", // for OpenSSL 3.x
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/local/lib/libssl.so", // custom installations
		"/lib64/libssl.so",         // RHEL/CentOS
	}

	for _, p := range possiblePaths {
		if _, err := os.Stat(p); err == nil {
			glog.Infof("found libssl at: %s", p)
			return p, nil
		}
	}

	return "", fmt.Errorf("libssl.so not found")
}

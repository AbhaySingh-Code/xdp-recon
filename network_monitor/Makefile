CLANG := clang
CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86

all: monitor.skel.h

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

monitor.bpf.o: monitor.bpf.c parser.h common.h vmlinux.h
	$(CLANG) $(CFLAGS) -c monitor.bpf.c -o monitor.bpf.o

monitor.skel.h: monitor.bpf.o
	bpftool gen skeleton monitor.bpf.o name monitor_bpf > monitor.skel.h

clean:
	rm -f monitor.bpf.o monitor.skel.h vmlinux.h
CLANG := clang 
CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86

all: tc.bpf.o 

tc.bpf.o: tc_monitor.bpf.c 
	$(CLANG) $(CFLAGS) -c tc_monitor.bpf.c -o tc.bpf.o 

clean: 
	rm -f tc.bpf.o
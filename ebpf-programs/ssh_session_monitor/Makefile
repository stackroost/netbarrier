CLANG ?= clang
BPFTOOL ?= bpftool
TARGET = ssh_session_monitor
SRC = ssh_session_monitor.c
OBJ = ../../bin/$(TARGET).o
VMLINUX = vmlinux.h

all: $(OBJ)

$(OBJ): $(SRC) $(VMLINUX)
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -c $(SRC) -o $(OBJ)

$(VMLINUX):
	@echo "Generating vmlinux.h..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

clean:
	rm -f $(OBJ) $(VMLINUX)

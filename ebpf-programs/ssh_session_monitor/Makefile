# ebpf-programs/ssh_session_monitor/Makefile

CLANG ?= clang
TARGET = ssh_session_monitor
SRC = ssh_session_monitor.c
OBJ = ../../bin/$(TARGET).o

all: $(OBJ)

$(OBJ): $(SRC)
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -c $(SRC) -o $(OBJ)

clean:
	rm -f $(OBJ)

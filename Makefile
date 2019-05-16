obj-m += tfe_kmod_core.o
tfe_kmod_core-y := src/core.o src/util.o src/proc.o src/cmsg.o
ccflags-y := -DDEBUG

all:
	 make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	 make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

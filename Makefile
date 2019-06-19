obj-m += tfe_kmod_core.o
tfe_kmod_core-y := core.o util.o stat.o cmsg.o
ccflags-n := -DDEBUG -g

all:
	 make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	 make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

obj-m += tfe_kmod_core.o
tfe_kmod_core-y := inet_ntop.o core.o

all:
	 make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	 make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

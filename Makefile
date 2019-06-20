obj-m += tfe_kmod.o
tfe_kmod-y := core.o util.o stat.o cmsg.o
ccflags-n := -DDEBUG -g
version := $(shell git log --pretty=format:'%h' -n 1)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
package:
	sed -ri 's,(PACKAGE_VERSION=).*,\1\"$(version)\",' dkms.conf
	dkms add ./
	dkms mkrpm tfe-kmod/$(version) --source-only

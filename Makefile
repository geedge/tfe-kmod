obj-m += tfe_kmod.o
tfe_kmod-y := core.o util.o stat.o cmsg.o
ccflags-n := -DDEBUG -g
version := $(shell git log --pretty=format:'%h' -n 1)

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PREFIX ?= /usr
DESTDIR ?=
SRCDIR ?= $(PREFIX)/src
DKMSDIR ?= $(SRCDIR)/wireguard
DEPMOD ?= depmod

all: module
debug: module-debug

version.h:
	@export GIT_CEILING_DIRECTORIES="$$(readlink -f ../..)" && \
		ver="#define TFE_KMOD_VERSION \"$$(git describe --dirty 2>/dev/null)\"" && \
		[ "$$(cat version.h 2>/dev/null)" != "$$ver" ] && \
		echo "$$ver" > version.h && \
		git update-index --assume-unchanged version.h || true

dkms.conf:
	@export GIT_CEILING_DIRECTORIES="$$(readlink -f ../..)" && \
		ver="$$(git describe --dirty 2>/dev/null)" && \
		. ./dkms.conf && \
		[ "$$PACKAGE_VERSION" != "$$ver" ] && \
		sed -i "s/PACKAGE_VERSION=.*/PACKAGE_VERSION=\"$$ver\"/" dkms.conf && \
		git update-index --assume-unchanged dkms.conf || true

module: version.h
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
package:
	dkms add ./
	dkms mkrpm tfe-kmod/$(version) --source-only

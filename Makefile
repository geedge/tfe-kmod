obj-m += tfe-kmod.o
tfe-kmod-y := core.o util.o stat.o cmsg.o
ccflags-n := -DDEBUG -g
version := $(shell git log --pretty=format:'%h' -n 1)

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PREFIX ?= /usr
DESTDIR ?=
SRCDIR ?= $(PREFIX)/src
VERSION ?= $(subst -,.,$(shell git describe --dirty 2>/dev/null))
DKMSDIR ?= $(SRCDIR)/tfe-kmod
DEPMOD ?= depmod

.PHONY: all module clean dkms-install dkms-package version.h dkms.conf

all: module
debug: module-debug

version.h:
	@export GIT_CEILING_DIRECTORIES="$$(readlink -f ../..)" && \
		ver="#define TFE_KMOD_VERSION \"$(VERSION)\"" && \
		[ "$$(cat version.h 2>/dev/null)" != "$$ver" ] && \
		echo "$$ver" > version.h && \
		git update-index --assume-unchanged version.h || true

dkms.conf:
	@export GIT_CEILING_DIRECTORIES="$$(readlink -f ../..)" && \
		ver=$(VERSION) && \
		. ./dkms.conf && \
		[ "$$PACKAGE_VERSION" != "$$ver" ] && \
		sed -i "s/PACKAGE_VERSION=.*/PACKAGE_VERSION=\"$$ver\"/" dkms.conf && \
		git update-index --assume-unchanged dkms.conf || true

module: version.h
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean


DKMS_SOURCES := Makefile dkms.conf $(wildcard *.c *.h)

dkms-install: $(DKMS_SOURCES)
	@$(foreach f,$(DKMS_SOURCES),install -v -m0644 -D $(f) $(DESTDIR)$(DKMSDIR)/$(f);)

dkms-package: dkms-install
	dkms add $(DKMSDIR)
	dkms mkrpm -m tfe-kmod -v $(VERSION) --source-only

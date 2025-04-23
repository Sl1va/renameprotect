KPATH := /lib/modules/$(shell uname -r)/build
obj-m := renameprotect.o

all: modules

modules:
	$(MAKE) -C $(KPATH) M=$$PWD modules

modules_install:
	$(MAKE) -C $(KPATH) M=$$PWD modules_install

clean:
	$(MAKE) -C $(KPATH) M=$$PWD clean

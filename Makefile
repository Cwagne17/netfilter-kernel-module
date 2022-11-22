##################################################
# Usage: $ make args="<filename_w/o_.c>"         #
# E.g:   $ make args="hello" for file "hello.c"  #
##################################################
obj-m += ${args}.o

LIBDIR=/lib/modules/${shell uname -r}/build

all:
	make -C $(LIBDIR) M=$(PWD) modules
clean:
	make -C $(LIBDIR) M=$(PWD) clean
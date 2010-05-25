# Makefile for xtrlock - X Transparent Lock
# This Makefile provided for those of you who lack a functioning xmkmf.
#
# Copyright (C)1993,1994 Ian Jackson
#
# This is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.


CC ?= gcc
override CFLAGS += -Wall
override LDFLAGS += -L/usr/X11R6/lib 
override LDLIBS += -lX11 -lpam

INSTALL=install

first : xtrlock

clean :
	rm -fr *.o

distclean:
	rm -fr *.o xtrlock

install:	xtrlock
		$(INSTALL) -c -m 755 xtrlock /usr/bin/X11

install.man:
		$(INSTALL) -c -m 644 xtrlock.man /usr/man/man1/xtrlock.1x

# 
##########################################################
xtrlock:	xtrlock.o

xtrlock.o:	xtrlock.c lock.bitmap mask.bitmap



PROGRAM = proxytweak
CC=cc

L_SSL=-lssl -lcrypto
LIBS=-lpthread $(L_SSL)
DEBUG=-ggdb -DDEBUG -Og
CFLAGS=-c -O2 -Wall -Wextra $(DEBUG)
LDFLAGS=-O2 $(LIBS) $(DEBUG)

OBJS=main.o server.o helper.o


all: $(PROGRAM)

$(PROGRAM): $(OBJS)
	$(CC) -o $@ $(LDFLAGS) $^
%.o: %.c
	$(CC) -o $@ $(CFLAGS) $<

tags: *.c
	ctags -R --kinds-C=+pxD *.h *.c
# system tags
TAGS:
	ctags -R  --kinds-C=m   -f TAGS /usr/include/sys /usr/include/*.h /usr/include/bits /usr/include/asm /usr/include/linux

.PHONY: clean backup
clean:
	-rm $(OBJS) $(PROGRAM) tags TAGS

backup:
	-cp -au *.c *.h Makefile ~/tmp2/projects/proxytweak

PROGRAM = proxytweak
CC ?=cc

L_SSL ?=-lssl -lcrypto
LIBS ?=-lpthread $(L_SSL)
DEBUG ?=-DDEBUG -ggdb -Og -fanalyzer
CFLAGS ?=-c -Wall -Wextra $(DEBUG)
LDFLAGS ?=$(LIBS)

OBJS ?=main.o server.o socket_helper.o tls_helper.o http_helper.o tweak.o


all: $(PROGRAM)

$(PROGRAM): $(OBJS)
	$(CC) -o $@ $(LDFLAGS) $^
%.o: %.c %.h
	$(CC) -o $@ $(CFLAGS) $<

tags: *.c
	ctags -R --kinds-C=+pxD *.h *.c
# system tags
TAGS:
	ctags -R  --kinds-C=m   -f TAGS /usr/include/sys /usr/include/*.h /usr/include/bits /usr/include/asm /usr/include/linux

make.d: *.h
	$(CC) $(CPPFLAGS) $(CFLAGS) *.c -MM > $@

include make.d

.PHONY: clean backup
clean:
	-rm $(OBJS) $(PROGRAM) make.d

distclean: clean
	-rm  tags TAGS

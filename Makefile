PROGRAM = proxytweak
CC ?=cc

ifdef NDEBUG
	DEBUG := -DNDEBUG -O3 -flto
	LDFLAGS += -O3 -flto -s
else
	DEBUG ?=-ggdb -Og -fanalyzer -Wpedantic
endif

LIBS ?=-lssl -lcrypto -lpthread

ifneq (,$(findstring mingw,$(CC)))
LIBS += -lws2_32
LDFLAGS += -static
CFLAGS += -D_POSIX
endif

CFLAGS +=-c -Wall -Wextra $(DEBUG)
LDFLAGS +=$(LIBS)

OBJS ?=main.o server.o socket_helper.o tls_helper.o http_helper.o tweak.o
all: $(PROGRAM)

$(PROGRAM): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)
%.o: %.c %.h
	$(CC) -o $@ $(CFLAGS) $<

tweak.h: tweak_in.h
	$(CC) -E -dD $^ | grep -Ev "# |#define _|linux|unix" > tweak.h

tags: *.c
	ctags -R --kinds-C=+pxD *.h *.c
# system tags
TAGS:
	ctags -R  --kinds-C=m   -f TAGS /usr/include/sys /usr/include/*.h /usr/include/bits /usr/include/asm /usr/include/linux

make.d: *.c *.h tweak.h
	$(CC) $(CPPFLAGS) $(CFLAGS) *.c -MM > $@

include make.d

# for code completion and language servers (libclang clangd)
complete: compile_commands.json .clang_complete tags
built_in_defs.hpp:
	$(CC) -E -dM <<<aa - -o $@

COMPLETE_DEFINES = -imacros built_in_defs.hpp -I /usr/x86_64-w64-mingw32/include
# for completer .clang_complete
.clang_complete: built_in_defs.hpp
	echo -ne "$(CFLAGS)\n$(COMPLETE_DEFINES)\n" > $@

# for clangd
compile_commands.json: built_in_defs.hpp
	echo [{"directory": "'$(PWD)'","command": "'$(CC) $(CFLAGS) $(COMPLETE_DEFINES)'","file": "'*.c sim/gdb/*.c'"}] > $@

.PHONY: clean backup complete
clean:
	-rm $(OBJS) $(PROGRAM) $(PROGRAM).exe make.d tweak.h

distclean: clean
	-rm  tags TAGS compile_commands.json .clang_complete built_in_defs.hpp

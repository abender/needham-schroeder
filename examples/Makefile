needham_dir = ..

SOURCES:= client.c daemon.c server.c
OBJECTS:= $(patsubst %.c, %.o, $(SOURCES))
EXECUTABLES:= $(patsubst %.c, %, $(SOURCES))
CFLAGS:=-Wall -g
CPPFLAGS:=-I$(needham_dir)
LDFLAGS:= -L$(needham_dir)
LDLIBS:=-lneedham

.PHONY: all

all:	$(EXECUTABLES)

clean:
	rm -rf $(EXECUTABLES)
	for exe in $(EXECUTABLES) ; do \
		rm -rf $(addsuffix .dSYM,$$exe) ; \
	done

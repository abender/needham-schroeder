needham_dir = ..

SOURCES:= client.c daemon.c server.c
OBJECTS:= $(patsubst %.c, %.o, $(SOURCES))
EXECUTABLES:= $(patsubst %.c, %, $(SOURCES))
CFLAGS:=-Wall -g -I$(needham_dir)
LDFLAGS:= -L$(needham_dir) -lneedham

.PHONY: all

all:	$(EXECUTABLES)

clean:
	@rm -f $(EXECUTABLES)
CC:=gcc
CFLAGS:=-Wall -g -DWITH_AES_DECRYPT -DNSDEBUG
SOURCES:= needham.c ns_util.c rin_wrapper.c
OBJECTS:= $(patsubst %.c, %.o, $(SOURCES)) rijndael/rijndael.o sha2/sha2.o
HEADERS:= needham.h ns_util.h rin_wrapper.h
LIB:=libneedham.a
SUBDIRS:=rijndael sha2 examples
ARFLAGS:=cru

.PHONY: clean all dirs

all: $(LIB) dirs

dirs:	$(SUBDIRS)
	for dir in $^; do \
		$(MAKE) -C $$dir ; \
	done

$(LIB): $(OBJECTS)
	$(AR) $(ARFLAGS) $@ $^ 
	ranlib $@

clean:
	@rm -f $(OBJECTS) $(LIB)
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir clean ; \
	done
  
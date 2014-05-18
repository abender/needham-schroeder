CC:=gcc
CFLAGS:=-Wall -g -DWITH_AES_DECRYPT -DNS_DEBUG
SOURCES:= ccm.c needham.c ns_util.c rin_wrapper.c
OBJECTS:= $(patsubst %.c, %.o, $(SOURCES)) aes/rijndael.o sha2/sha2.o
HEADERS:= ccm.h needham.h ns_util.h rin_wrapper.h
LIB:=libneedham.a
SUBDIRS:=aes sha2 examples
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
  
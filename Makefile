CC:=gcc
CFLAGS:=-Wall -g -DWITH_AES_DECRYPT -DNSDEBUG
SOURCES:= needham.c ns_util.c rin_wrapper.c rijndael/rijndael.c sha2/sha2.c
OBJECTS:= $(patsubst %.c, %.o, $(SOURCES))
HEADERS:= needham.h ns_util.h rin_wrapper.h
LIB:=libneedham.a
EXAMPLES:=examples
ARFLAGS:=cru

.PHONY: clean all $(EXAMPLES)

all: $(LIB) $(EXAMPLES)

$(LIB): $(OBJECTS)
	$(AR) $(ARFLAGS) $@ $^ 
	ranlib $@

$(EXAMPLES): $(LIB)
	$(MAKE) -C $(EXAMPLES)

clean:
	@rm -f $(OBJECTS) $(LIB)
	$(MAKE) -C $(EXAMPLES) clean
  
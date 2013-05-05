CC:=gcc
CFLAGS:=-Wall -g -DWITH_AES_DECRYPT
SOURCES:= needham.c util.c rin_wrapper.c rijndael/rijndael.c
OBJECTS:= $(patsubst %.c, %.o, $(SOURCES))
HEADERS:= needham.h rin_wrapper.h util.h
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
  
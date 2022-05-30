CPPFLAGS += -I /usr/include/python3.7m
LIBS=-lpython3.7m 

COMPOSANT = chiffrage_component

LIBSO = ${COMPOSANT}.so
LIBSO_OBJS = ${COMPOSANT}.o micro-ecc/uECC.o

include ../gcc.mk
include ../pybind11.mk


all: $(LIBSO)
clean:
	rm -f ${LIBSO}  ${LIBSO_OBJS}


${DESTINATION_LIBSO}: ${LIBSO}
	cp $< $@

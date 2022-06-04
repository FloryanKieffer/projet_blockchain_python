CPPFLAGS += -I /usr/include/python3.7m 
CPPFLAGS += -std=c++11
LIBS=`python3-config --ldflags` -L cryptopp -l cryptopp
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

CPPFLAGS += -I /usr/include/python3.7m
LIBS=-lpython3.7m 

COMPOSANT = members_component


LIBSO = ${COMPOSANT}.so
LIBSO_OBJS = ${COMPOSANT}.o

DESTINATION_LIBSO=../components/${LIBSO}

all: ${DESTINATION_LIBSO}

include ../gcc.mk
include ../pybind11.mk
include ../json.mk


	
clean:
	rm -f ${LIBSO}  ${LIBSO_OBJS} ${DESTINATION_LIBSO}


${DESTINATION_LIBSO}: ${LIBSO}
	cp $< $@


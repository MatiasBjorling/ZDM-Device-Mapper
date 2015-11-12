#* ---------------------------------------------------------------------------------------------
#* Copyright (c) 2014 Seagate Technologies
#* All rights reserved.
#* ---------------------------------------------------------------------------------------------

## Tools ##
RM		= rm -f

CC=gcc
CFLAGS=-I. -Wall
LD=gcc

CPP=g++
CPPFLAGS=-I. -Wall


DEFINES     	+= -D_LARGEFILE64_SOURCE
DEFINES     	+= -D_FILE_OFFSET_BITS=64

CFLAGS          += -Wno-unused-function -I../h
CPPFLAGS        += -Wno-unused-function -I../h

## Debug [Conditional compilation] ##
ifeq ($(DEBUG),1)
DEFINES     	+= -DDEBUG
endif

LIBTITLE        = libzdm
LIBNAME         = $(LIBTITLE).so
STATICLIBNAME   = $(LIBTITLE).a


## Compiling/Linking Options ##
INCPATH		+= -I../h
INCFILES	+=
LFLAGS		+= -shared -Wl,-soname,$(LIBNAME)
LIBS		+=

## Source Files ##
SOURCES		= crc64 is_mounted libcrc libsort libzdm zbc-ctrl


## Output directory ##
OBJECTS_DIR	=
OBJECTS		= $(addsuffix .o, $(SOURCES))

ifeq ($(VERBOSE),1)
BE_QUIET=
else
BE_QUIET=@
endif


##
## Compiling Rules
##

all: $(STATICLIBNAME)

$(LIBNAME): $(OBJECTS)
	@echo "Linking $@"
	$(BE_QUIET)$(LD) $(LFLAGS) $(LIBS) -o $@ $^

$(STATICLIBNAME): $(OBJECTS)
	@echo "Creating static library $@"
	$(BE_QUIET)$(AR) $(ARFLAGS) $@ $^

%.o: %.cpp $(INCFILES)
	@echo "Compiling $<"
	$(BE_QUIET)$(CPP) $(CPPFLAGS) $(DEFINES) $(INCPATH) -c $< -o $@

%.o: %.c $(INCFILES)
	@echo "Compiling $<"
	$(BE_QUIET)$(CC) $(CCFLAGS) $(DEFINES) $(INCPATH) -c $< -o $@

clean:
	$(BE_QUIET)$(RM) $(OBJECTS)

distclean: clean
	$(BE_QUIET)$(RM) $(LIBNAME)* $(STATICLIBNAME)

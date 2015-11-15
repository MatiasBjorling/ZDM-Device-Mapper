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

CFLAGS          += -Wno-unused-function
CPPFLAGS        += -Wno-unused-function

INCPATH         += -I../h

## Debug [Conditional compilation] ##
ifeq ($(DEBUG),1)
DEFINES     	+= -DDEBUG
endif

## Build Verbosity ##
ifeq ($(VERBOSE),1)
BE_QUIET=
else
BE_QUIET=@
endif

## Targets ##
TARGETS		+= zdmadm zdm-status zdm-zones zdm-mlog

## Source Files ##
CPP_SOURCES	 =
C_SOURCES	 =
SOURCES		 = $(addsuffix .c, $(C_SOURCES)) $(addsuffix .cpp, $(CPP_SOURCES))

## Header Files ##
INCFILES         =

## Output directory ##
OBJECTS_DIR	 =
OBJECTS		 = $(addsuffix .o, $(C_SOURCES)) $(addsuffix .o, $(CPP_SOURCES))

## Libraries ##
LIBS += `pkg-config libssl --libs`
LIBS += `pkg-config uuid --libs`
LIBS += -L../lib -lzdm

# NOTE: for sha/uuid support:
#   sudo apt-get install libssl-dev
#   sudo apt-get install uuid-dev

##
## Compiling Rules
##

all: $(TARGETS)

zdmadm: zdmadm.c
	@echo "Building $@"
	$(BE_QUIET)$(CC) $(DEFINES) $(CFLAGS) $(INCPATH) $< -o $@ $(LIBS)

zdm-mlog: zdm-mlog.c
	@echo "Building $@"
	$(BE_QUIET)$(CC) $(DEFINES) $(CFLAGS) $(INCPATH) $< -o $@ $(LIBS)

zdm-status: zdm-status.c
	@echo "Building $@"
	$(BE_QUIET)$(CC) $(DEFINES) $(CFLAGS) $(INCPATH) $< -o $@

zdm-zones: zdm-zones.c
	@echo "Building $@"
	$(BE_QUIET)$(CC) $(DEFINES) $(CFLAGS) $(INCPATH) $< -o $@

test: $(TARGETS)
	echo "TODO"

check: test

clean:
	$(BE_QUIET)$(RM) $(OBJECTS)

distclean: clean
	$(BE_QUIET)$(RM) $(TARGETS)

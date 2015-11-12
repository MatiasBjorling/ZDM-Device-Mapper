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

CFLAGS          += -Wno-unused-function -I./h
CPPFLAGS        += -Wno-unused-function -I./h

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

LIBDIRS = lib
LIBCLEAN = $(addsuffix .clean,$(LIBDIRS))
LIBMORECLEAN = $(addsuffix .distclean,$(LIBDIRS))

SUBDIRS = zdmonitor
SUBCLEAN = $(addsuffix .clean,$(SUBDIRS))
SUBMORECLEAN = $(addsuffix .distclean,$(SUBDIRS))

## Targets ##
TARGETS		+= zdmadm zdm-status zdm-zones zdm-mlog

## Source Files ##
CPP_SOURCES	 =
C_SOURCES	 = zdmadm
SOURCES		 = $(addsuffix .c, $(C_SOURCES)) $(addsuffix .cpp, $(CPP_SOURCES))

## Header Files ##
INCFILES         = dm-zoned.h libcrc.h libsort.h libzoned.h libzoned.c
INCFILES        += list.h utypes.h libzdm.h zbc-ctrl.h is_mounted.h

## Output directory ##
OBJECTS_DIR	 =
OBJECTS		 = $(addsuffix .o, $(C_SOURCES)) $(addsuffix .o, $(CPP_SOURCES))

## Libraries ##
LIBS += `pkg-config libssl --libs`
LIBS += `pkg-config uuid --libs`
LIBS += -L./lib -lzdm

# NOTE: for sha/uuid support:
#   sudo apt-get install libssl-dev
#   sudo apt-get install uuid-dev

##
## Compiling Rules
##

.PHONY: subdirs $(SUBDIRS)
.PHONY: libdirs $(LIBDIRS)
.PHONY: clean $(SUBCLEAN)
.PHONY: clean $(LIBCLEAN)
.PHONY: distclean $(SUBMORECLEAN)
.PHONY: distclean $(LIBMORECLEAN)


all:  libdirs $(TARGETS) subdirs

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

%.o: %.cpp $(INCFILES)
	@echo "Compiling $<"
	$(BE_QUIET)$(CPP) $(DEFINES) $(CPPFLAGS) $(INCPATH) -c $< -o $@

%.o: %.c $(INCFILES)
	@echo "Compiling $<"
	$(BE_QUIET)$(CC) $(DEFINES) $(CFLAGS) $(INCPATH) -c $< -o $@

subdirs: $(SUBDIRS)
libdirs: $(LIBDIRS)

$(SUBDIRS):
	@echo "Building $@"
	$(BE_QUIET)cd $@; qmake; cd ..
	$(BE_QUIET)$(MAKE) --quiet -C $@

$(LIBDIRS):
	@echo "Building $@"
	$(BE_QUIET)$(MAKE) --quiet -C $@

test: $(TARGETS)
	echo "TODO"

check: test

clean: $(SUBCLEAN) $(LIBCLEAN)
	$(BE_QUIET)$(RM) $(OBJECTS)

$(SUBCLEAN): %.clean:
	$(BE_QUIET)$(MAKE) --quiet -C $* clean

$(LIBCLEAN): %.clean:
	$(BE_QUIET)$(MAKE) --quiet -C $* clean

distclean: clean $(SUBMORECLEAN) $(LIBMORECLEAN)
	$(BE_QUIET)$(RM) $(TARGETS)

$(SUBMORECLEAN): %.distclean:
	$(BE_QUIET)$(MAKE) --quiet -C $* distclean

$(LIBMORECLEAN): %.distclean:
	$(BE_QUIET)$(MAKE) --quiet -C $* distclean


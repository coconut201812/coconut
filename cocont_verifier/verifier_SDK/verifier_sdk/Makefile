#!/usr/bin/make -f

#define variables
IPP_API_INCLUDE_DIR = ../ext/ipp/include
EXAMPLE_INSTALL_DIR = $(epidinstalldir)/bin
DATA_INSTALL_DIR = $(epidinstalldir)/data
NON_SPLIT_DATA_INSTALL_DIR = $(DATA_INSTALL_DIR)/non_split
SPLIT_DATA_INSTALL_DIR = $(DATA_INSTALL_DIR)/split


VERIFYSIG_INCLUDE_DIR = ./verifysig
VERIFYSIG_SRC = $(wildcard ./verifysig/src/*.c)
VERIFYSIG_OBJ = $(VERIFYSIG_SRC:.c=.o)
VERIFYSIG_SO = ./verifysig/src/libverifysig.so

LIB_UTIL_DIR = ./util/src
LIB_IPPCP_DIR = ../ext/ipp/sources/ippcp/src
LIB_MEMBER_DIR = ../epid/member
LIB_VERIFIER_DIR = ../epid/verifier
LIB_COMMON_DIR = ../epid/common

JNI_PATH = /usr/java/jdk-10.0.2/include
JNI_MD_PATH = /usr/java/jdk-10.0.2/include/linux

#set linker flags
LIB_INCLUDE += -L$(LIB_UTIL_DIR) \
	-L$(LIB_IPPCP_DIR) \
	-L$(LIB_COMMON_DIR) \
	-lcommon \
	-lippcp -lutil

ifneq ($(TSS_PATH),)
	LIB_INCLUDE += -L$(TSS_PATH) -ltss -lcrypto
endif

ifeq ($(TINY),yes)
	LIB_INCLUDE += -L$(LIB_MEMBER_DIR) -lmath -ltiny_stdlib
endif

CFLAGS += -Wno-sign-compare -Wno-enum-compare

$(VERIFYSIG_SO): $(VERIFYSIG_OBJ)
	$(CC)  -fpic -shared -o $@ $^ -L$(LIB_VERIFIER_DIR) -lverifier $(LIB_INCLUDE)

$(VERIFYSIG_OBJ): %.o: %.c
	$(CC) -o $@ $(CFLAGS) -I$(JNI_PATH)  \
			-I$(JNI_MD_PATH) \
			-I$(LIB_UTIL_DIR)/../.. \
        	-I$(LIB_VERIFIER_DIR)/../.. \
			-I$(VERIFYSIG_INCLUDE_DIR) \
			-I$(IPP_API_INCLUDE_DIR) -c $^


#target part
build: all install

all: $(VERIFYSIG_SO)

install:
	mkdir -p '$(DATA_INSTALL_DIR)'
	find data/. \( -iname '*.bin' -o -iname '*.dat' -o \
		-iname '*.md' \) -a ! -iname '*-priv.dat' -print0 \
		| xargs -0 cp --parents -t '$(DATA_INSTALL_DIR)'
	mv '$(DATA_INSTALL_DIR)/data' '$(NON_SPLIT_DATA_INSTALL_DIR)'
	find split_data/. \( -iname '*.bin' -o -iname '*.dat' -o \
		-iname '*.md' \) -a ! -iname '*-priv.dat' -print0 \
		| xargs -0 cp --parents -t '$(DATA_INSTALL_DIR)'
	mv '$(DATA_INSTALL_DIR)/split_data' '$(SPLIT_DATA_INSTALL_DIR)'
	mkdir -p '$(EXAMPLE_INSTALL_DIR)'

	cp $(VERIFYSIG_SO) '$(EXAMPLE_INSTALL_DIR)'

clean:
	rm -f $(VERIFYSIG_OBJ) \
		$(VERIFYSIG_SO)

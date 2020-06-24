#
# INTEL CONFIDENTIAL
# Copyright(c) 2011-2016 Intel Corporation. All rights reserved.
#
# The source code contained or described herein and all documents related to
# the source code ("Material") are owned by Intel Corporation or its suppliers
# or licensors. Title to the Material remains with Intel Corporation or its
# suppliers and licensors. The Material contains trade secrets and proprietary
# and confidential information of Intel or its suppliers and licensors. The
# Material is protected by worldwide copyright and trade secret laws and treaty
# provisions. No part of the Material may be used, copied, reproduced, modified,
# published, uploaded, posted, transmitted, distributed, or disclosed in any
# way without Intel's prior express written permission.
#
# No license under any patent, copyright, trade secret or other intellectual
# property right is granted to or conferred upon you by disclosure or delivery
# of the Materials, either expressly, by implication, inducement, estoppel or
# otherwise. Any license under such intellectual property rights must be
# express and approved by Intel(R) in writing.
#

include ../buildenv.mk

TSYSCALL_LIB_NAME = libsgx_tsyscall.a

Enclave_C_Files := $(wildcard *.c) 
Enclave_C_Objects := $(Enclave_C_Files:.c=.o)

SGX_LIBRARY_PATH := $(SGX_SDK)/lib64

Enclave_Include_Paths = -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx -I$(TOPDIR)/include -I$(TOPDIR)/inc 
Enclave_C_Flags := -O2 -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++03 -nostdinc++

# Enclave_Link_Flags := -shared -O2 -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) -L$(TOPDIR)/lib \
#         -Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
#         -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -lsgx_tservice -lsgx_mbedcrypto -lsgx_mbedtls -lsgx_mbedx509 -Wl,--end-group \
#         -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
#         -Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
#         -Wl,--defsym,__ImageBase=0 \
#         -Wl,--version-script=enclave.lds

.PHONY: all
all: $(TSYSCALL_LIB_NAME)
	cp $(TSYSCALL_LIB_NAME) $(TOPDIR)/$(LIBDIR)/

$(TSYSCALL_LIB_NAME): $(Enclave_C_Objects)
	$(AR) rcsD $@ $^

$(Enclave_C_Objects): %.o :%.c
	$(CC) $(Enclave_C_Flags) -c $< -o $@

.PHONY: clean
clean:
	@$(RM) $(OBJ) $(LIBNAME)

.PHONY: rebuild
rebuild: 
	$(MAKE) clean 
	$(MAKE) all

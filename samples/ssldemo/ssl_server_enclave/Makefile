include ../../../buildenv.mk

ENCLAVE_NAME = libssl_server_enclave.so
TARGET = libssl_server_enclave.signed.so

Enclave_C_Files := $(wildcard *.c) 
Enclave_C_Objects := $(Enclave_C_Files:.c=.o)
Enclave_Config_File := enclave.xml

SGX_LIBRARY_PATH := $(SGX_SDK)/lib64

Enclave_Include_Paths = -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx -I$(TOPDIR)/mbedtls/include -I$(TOPDIR)/inc -I$(TOPDIR)/tsyscall 
Enclave_C_Flags := -O2 -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++03 -nostdinc++

Enclave_Link_Flags := -shared -O2 -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) -L$(TOPDIR)/lib \
        -Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
        -Wl,--start-group -lsgx_tsyscall -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -lsgx_tservice -lsgx_mbedcrypto -lsgx_mbedtls -lsgx_mbedx509 -Wl,--end-group \
        -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
        -Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
        -Wl,--defsym,__ImageBase=0 \
        -Wl,--version-script=enclave.lds

all: $(TARGET)
       
$(TARGET): ssl_server_enclave_t.o $(Enclave_C_Objects)
	$(CXX) $^ -MMD -o $(ENCLAVE_NAME) $(Enclave_Link_Flags)	
	$(SGX_ENCLAVE_SIGNER) sign -key isv_private_key.pem -enclave $(ENCLAVE_NAME) -out $@ -config $(Enclave_Config_File)
	@cp $@ $(TOPDIR)/$(OUTDIR)/

$(Enclave_C_Objects): %.o: %.c
	$(CC) $(Enclave_C_Flags) -c -MMD $< -o $@

ssl_server_enclave_t.o: ssl_server_enclave_t.c
	$(CC) $(Enclave_C_Flags) -c -MMD $< -o $@

ssl_server_enclave_t.c: $(SGX_EDGER8R) ssl_server_enclave.edl 
	$(SGX_EDGER8R) --use-prefix --trusted ssl_server_enclave.edl --search-path $(SGX_SDK)/include 

clean:
	$(RM) *.o *.d ssl_server_enclave_t.* $(ENCLAVE_NAME) $(TARGET)
	#$(RM) *.o *.d $(ENCLAVE_NAME) $(TARGET)

.PHONY: all clean

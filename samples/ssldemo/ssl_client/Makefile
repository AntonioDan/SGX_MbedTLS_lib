include ../../../buildenv.mk

TARGET = ssl_client

RM = rm -f

INC = -I$(SGX_SDK)/include
LIB := -lsgx_urts -lsgx_uae_service -L$(SGX_SDK)/lib64 
CXXFLAGS += -ggdb $(INC) $(LIB)
CFLAGS += -ggdb $(INC) $(LIB)

####################### App Objects ##################
all: $(TARGET)
	
ssl_client_enclave_u.o: ssl_client_enclave_u.c
	@$(CC) $(CFLAGS) -c $< -o $@

ssl_client_enclave_u.c: ../ssl_client_enclave/ssl_client_enclave.edl
	$(SGX_EDGER8R) --use-prefix --untrusted $< --search-path ../ssl_client_enclave --search-path $(SGX_SDK)/include

SRC_CPP=$(wildcard *.cpp)
SRC_C=$(wildcard *.c)

SRC_OBJ += $(SRC_CPP:.cpp=.o)
SRC_OBJ += $(SRC_C:.c=.o)

$(TARGET): ssl_client_enclave_u.o $(SRC_OBJ)
	$(CXX) $^ $(CXXFLAGS) -o $@	
	@mv $@ $(TOPDIR)/$(OUTDIR)/

clean:	
	$(RM) $(TARGET) *.o *_u.c *_u.h

.PHONY = all clean

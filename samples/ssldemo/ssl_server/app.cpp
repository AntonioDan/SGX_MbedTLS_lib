#include <stdio.h>

#include "sgx_urts.h"
#include "sgx_error.h"
#include "ssl_server_enclave_u.h"

#define ENCLAVE_NAME "libssl_server_enclave.signed.so"

int main(int argc, char * argv[])
{
	int retval;
	sgx_status_t ret;	
	sgx_enclave_id_t eid;

	(void)argc;
	(void)argv;
	
	ret = sgx_create_enclave(ENCLAVE_NAME, 1, NULL, NULL, &eid, NULL);
	if (ret != SGX_SUCCESS) {
		printf("sgx_create_enclave() return error code 0x%x.\n", ret);
	}
	printf("succeed to load enclave.\n");

	ret = ssl_server_enclave_do_mbed_test(eid, &retval);
	if ((ret != SGX_SUCCESS) || (retval != 0)) {
		printf("fail to do enclave mbedcrypto MD5 test, ecall return 0x%04x, function return %d.\n", ret, retval);
		goto destroy_enclave;
	}	

	ret = ssl_server_enclave_do_ecdsa_test(eid, &retval);
	if ((ret != SGX_SUCCESS) || (retval != 0)) {
		printf("fail to do enclave mbedcrypto ECDSA test, ecall return 0x%04x, function return %d.\n", ret, retval);
	}

	ret = ssl_server_enclave_do_sha256_test(eid, &retval);
	if ((ret != SGX_SUCCESS) || (retval != 0)) {
		printf("fail to do enclave mbedcrypto ECDSA test, ecall return 0x%04x, function return %d.\n", ret, retval);
	}

	ret = ssl_server_enclave_do_ssl_server(eid, &retval);
	if ((ret != SGX_SUCCESS) || (retval != 0)) {
		printf("fail to do ssl server test, ecall return 0x%04x, function return %d.\n", ret, retval);
	}

destroy_enclave:
	sgx_destroy_enclave(eid);
	return 0;
}

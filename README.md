Trusted Mbed TLS library for Intel(R) SGX enclave 
====================================================

# Overview
This Mbed TLS library is customized to support Intel(R) SGX enclave environment, it enables SGX enclave developers to use Mbed TLS library interface as they do with normal application.

# Background
Intel(R) SGX is a trusted execution environment (TEE) which guarantees confidentiality and integrity. Intel provides SDK to support people to develop enclaves, it includes trusted runtime library and set of trusted library which can be linked as part of enclave binary. Intel(R) SGX SDK provides a trusted crypto library which is based on Intel(R) IPP library; it also provides SGXSSL library which is based on OpenSSL library. However, it doesn't provide trusted TLS library. This library aims to port Mbed TLS library to run in SGX enclave environment, so developers can use Mbed TLS library as they do in normal application. We believe trusted TLS library is an indispensable ingreident to protect network communication with TEE based solution. 

# Design Strategy
There are mainly two challenges to port Mbed TLS library to run in SGX enclave. Firstly, some instructions are disallowed to run in SGX enclave, this blocks those function flow where random instruction is involved. Second, SGX enclave by design doesn't support system call. Enclave developers need to develop OCALL routine to do system call, e.g. file operation related system call. To resolve the first problem, we need to avoid triggering random like instruction in enclave flow. Mbed TLS provides call function with which developer can customize operations like generating random buffer. To address the second problem, we develop OCALL stub for typical system call which are needed for Mbed TLS library, e.g. file operation, socket operation. 
We provide demo applications which execute TLS flow inside enclaves. In samples/ssldemo, there are two enclave projects, namely ssl_client_enclave and ssl_server_client, the two enclaves demo. TLS flow in enclave. We also provides examples how to call Mbed TLS function to do crypto. operation like MD5 checksum, ECDSA signing and verification, AES encryption.

# Build instruction
* Hardware Pre-requirements:
   SGX capable hardware platform with Intel(R) SGX enabled in BIOS.

* Software Pre-requirements:
1. To build the project from source code, you need to install Intel(R) SGX SDK. 
2. To execute the demo. application, you need to
   * install Intel(R) SGX driver and platform software. 
   Please refer to related SGX documents to know how to do this.

* Supported Operation systems:
  - Ubuntu 18.04 LTS Desktop 64bits

* Build steps:
1. in source code root directory, run "make"
2. when build complete, it would generate two output folders:
   "bin" subfolder - includes demo. application
   "lib" subfolder - include trusted Mbed TLS library (libsgx_mbedtls.a, libsgx_mbedx509.a, libsgx_mbedcrypto.a). It also includes a trusted library to support system call (libsgx_tsyscall.a), when this document is written, it mainly supports file and socket operations.

# Execution steps:
------
You can run demo. application with below stpes:
1. in "bin" sub-folder, execute "./ssl_server"
2. open a new concole, execute "./ssl_client"

# Content description:
* mbedtls: this is generally mbedtls 3.0 (https://github.com/ARMmbed/mbedtls.git) with modification to support Intel(R) SGX Enclave environment.
* inc: this is glibc header files to support building trusted mbedtls library.
* tsyscall: this is trusted library to support system call.
* samples: this includes sample projects.

# Contract:
If you have any questions or comments, you can send mail to antoniodanhu@gmail.com.






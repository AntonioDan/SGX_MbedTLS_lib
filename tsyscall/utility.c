#define __THROW 

#include <stdio.h>
#include <string.h>
#include <bits/types.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
//#include <select.h>

#include "sgx_error.h"


// #include "ssl_client_enclave_t.h"

#define BUFSIZE 256

/*
 * printf:
 *  Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char * fmt, ...)
{
    char buf[BUFSIZE] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZE, fmt, ap);
    va_end(ap);

    ocall_print_string(buf);

    return (int)strnlen(buf, BUFSIZE - 1) + 1;
}

int sprintf(char *str, const char *format, ...)
{
    char buf[BUFSIZE] = {'\0'};
    va_list ap;
    va_start(ap, format);
    vsnprintf(buf, BUFSIZE, format, ap);
    va_end(ap);

    ocall_sprint_string(str, buf);

    return (int)strnlen(buf, BUFSIZE - 1) + 1;
}

int puts(const char *s)
{
    ocall_puts(s);

    return (int)strlen(s);
}

int putchar(int c)
{
    ocall_putchar(c);

    return c;
}



int getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints,
                       struct addrinfo **res)
{
    int retval;
    sgx_status_t ret;    
    
    ret = ocall_getaddrinfo(&retval, node, service, hints, res);
    if (ret != SGX_SUCCESS) {        
        return EAI_FAIL;
    }
            
    return retval;
}

int socket(int domain, int type, int protocol)
{
    int retval;
    sgx_status_t ret;

    ret = ocall_socket(&retval, domain, type, protocol);
    if (ret != SGX_SUCCESS)
        return -1;
    
    return retval;
}

int connect(int sockfd, const struct sockaddr *addr,
                   socklen_t addrlen)
{
    int retval;
    sgx_status_t ret;

    printf("about to call ocall_connect()");

    ret = ocall_connect(&retval, sockfd, addr, addrlen);
    if (ret != SGX_SUCCESS) {
        printf("ocall_connect() failure, ocall return 0x%04x.\n", ret);
        return -1;
    }
        
    printf("ocall_connect() return %d.\n", retval);
    return retval;
}

int close(int fd)
{
    int retval;
    sgx_status_t ret;

    ret = ocall_close(&retval, fd);
    if (ret != SGX_SUCCESS)
        return -1;

    return retval;
}

void freeaddrinfo(struct addrinfo *res)
{
    ocall_freeaddrinfo(res);
}

int getsockopt(int sockfd, int level, int optname,
                      void *optval, socklen_t *optlen)
{
    int retval;
    sgx_status_t ret;
    socklen_t out_optlen;

    ret = ocall_getsockopt(&retval, sockfd, level, optname, optval, *optlen, &out_optlen);
    if (ret != SGX_SUCCESS)
        return -1;

    *optlen = out_optlen;

    return retval;
}

int setsockopt(int sockfd, int level, int optname,
                      const void *optval, socklen_t optlen)
{
    int retval;
    sgx_status_t ret;

    ret = ocall_setsockopt(&retval, sockfd, level, optname, optval, optlen);
    if (ret != SGX_SUCCESS)
        return -1;

    return retval;
}

int bind(int sockfd, const struct sockaddr *addr,
                socklen_t addrlen)
{
    int retval;
    sgx_status_t ret;
    
    ret = ocall_bind(&retval, sockfd, addr, addrlen);
    if (ret != SGX_SUCCESS) {        
        return -1;
    }        

    return retval;
}

int listen(int sockfd, int backlog)
{
    int retval;
    sgx_status_t ret;

    ret = ocall_listen(&retval, sockfd, backlog);
    if (ret != SGX_SUCCESS)
        return -1;

    return retval;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    int retval;
    sgx_status_t ret;

    ret = ocall_accept(&retval, sockfd, addr, addrlen);
    if (ret != SGX_SUCCESS)
        return -1;

    return retval;
}

int select(int nfds, fd_set *readfds, fd_set *writefds,
                  fd_set *exceptfds, struct timeval *timeout)
{
    int retval;
    sgx_status_t ret;

    ret = ocall_select(&retval, nfds, readfds, writefds, exceptfds, timeout);
    if (ret != SGX_SUCCESS)
        return -1;

    return retval;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                    struct sockaddr *src_addr, socklen_t *addrlen)
{
    ssize_t retval;
    sgx_status_t ret;

    ret = ocall_recvfrom(&retval, sockfd, buf, len, flags, src_addr, addrlen);
    if (ret != SGX_SUCCESS)
        return (ssize_t)-1;

    return retval;
}

ssize_t read(int fd, void *buf, size_t count)
{
    ssize_t retval;
    sgx_status_t ret;

    ret = ocall_read(&retval, fd, buf, count);
    if (ret != SGX_SUCCESS)
        return (ssize_t)-1;

    return retval;
}

ssize_t write (int fd, const void *buf, size_t count)
{
    ssize_t retval;
    sgx_status_t ret;

    ret = ocall_write(&retval, fd, buf, count);
    if (ret != SGX_SUCCESS)
        return (ssize_t)-1;

    return retval;
}

int shutdown(int sockfd, int how)
{
    int retval;
    sgx_status_t ret;

    ret = ocall_shutdown(&retval, sockfd, how);
    if (ret != SGX_SUCCESS)
        return -1;

    return retval;
}

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    int retval;
    sgx_status_t ret;

    ret = ocall_getsockname(&retval, sockfd, addr, addrlen);
    if (ret != SGX_SUCCESS)
        return -1;

    return retval;
}

// int printf(const char * fmt, ...)
// {
//     char buf[BUFSIZE] = {'\0'};
//     va_list ap;
//     va_start(ap, fmt);
//     vsnprintf(buf, BUFSIZE, fmt, ap);
//     va_end(ap);

//     ocall_print_string(buf);

//     return (int)strnlen(buf, BUFSIZE - 1) + 1;
// }

int fcntl_get(int fd, int cmd)
{
    int retval;
    sgx_status_t ret;

    ret = ocall_fcntl_get(&retval, fd, cmd);
    if (ret != SGX_SUCCESS)
        return -1;

    return retval;
}

int fcntl_set(int fd, int cmd, int option)
{
    int retval;
    sgx_status_t ret;

    ret = ocall_fcntl_set(&retval, fd, cmd, option);
    if (ret != SGX_SUCCESS)
        return -1;

    return retval;
}

// int fflush(FILE *stream)
// {
//     int retval;
//     sgx_status_t ret;

//     ret = ocall_fflush(&retval, stream);
//     if (ret != SGX_SUCCESS)
//         return -1;

//     return retval;
// }

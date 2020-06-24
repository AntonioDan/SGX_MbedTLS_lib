#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

void ocall_print_string(const char * str)
{
	printf("%s", str);
}

void ocall_sprint_string(char *buf, const char *str)
{
	sprintf(buf, "%s", str);
}

void ocall_puts(const char * str)
{
	puts(str);
}

void ocall_putchar(int c)
{
	putchar(c);
}

int ocall_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints,
                       struct addrinfo **res)
{
	return getaddrinfo(node, service, hints, res);
}

int ocall_socket(int domain, int type, int protocol)
{
	return socket(domain, type, protocol);
}

int ocall_connect(int sockfd, const struct sockaddr *addr,
                        socklen_t addrlen)
{
	return connect(sockfd, addr, addrlen);
}

int ocall_close(int fd)
{
	return close(fd);
}

void ocall_freeaddrinfo(struct addrinfo *res)
{
	freeaddrinfo(res);
}

int ocall_getsockopt(int sockfd, int level, int optname,
                    void *optval, socklen_t optlen, socklen_t *out_optlen)
// int ocall_getsockopt(int sockfd, int level, int optname,
//                         void *optval, socklen_t *optlen)
{
	int ret;
	socklen_t tmp_optlen = optlen;

	ret = getsockopt(sockfd, level, optname, optval, &tmp_optlen);

	*out_optlen = tmp_optlen;

	return ret;
}

int ocall_setsockopt(int sockfd, int level, int optname,
                        const void *optval, socklen_t optlen)
{
	return setsockopt(sockfd, level, optname, optval, optlen);
}

int ocall_bind(int sockfd, const struct sockaddr *addr,
                        socklen_t addrlen)
{
	int ret;
	
	ret = bind(sockfd, addr, addrlen);
	if (ret != 0)
	{
		printf("bind return error, error code is %d.\n", errno);
	}

	return ret;
}

int ocall_listen(int sockfd, int backlog)
{
	return listen(sockfd, backlog);
}

int ocall_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	return accept(sockfd, addr, addrlen);
}

int ocall_select(int nfds, fd_set *readfds, fd_set *writefds,
                  fd_set *exceptfds, struct timeval *timeout)
{
	return select(nfds, readfds, writefds, exceptfds, timeout);
}

ssize_t ocall_read(int fd, void *buf, size_t count)
{
	return read(fd, buf, count);
}
        
ssize_t ocall_write(int fd, const void *buf, size_t count)
{
	return write(fd, buf, count);
}
        
int ocall_shutdown(int sockfd, int how)
{
	return shutdown(sockfd, how);
}

int ocall_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	return getsockname(sockfd, addr, addrlen);
}

ssize_t ocall_recvfrom(int sockfd, void *buf, size_t len, int flags,
                    	struct sockaddr *src_addr, socklen_t *addrlen)
{
	return recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

int ocall_fcntl_get(int fd, int cmd)
{
	return fcntl(fd, cmd);
}

int ocall_fcntl_set(int fd, int cmd, int option)
{
	return fcntl(fd, cmd, option);
}

// int ocall_fflush(FILE *stream)
// {
// 	return fflush(stream);
// }
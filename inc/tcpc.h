#ifndef __TCP_H__

#define __TCP_H__

int tcp_socket(void);


int tcp_connect(int conn_fd, const char* ip, unsigned short port);


int tcp_bind(const char *ip_address, int ip_port, int sock_fd);


int tcp_listen(int sock_fd, int back_log);


int tcp_accept(int listen_fd);


int tcp_read(int sock_fd, char *buffer, int buffer_len, int flag);


int tcp_write(int sock_fd, char *data_buffer, int data_len, int flag);


int tcp_get_ip_address(char *hostname , char *ip);

int tcp_select(int fd);

char *tcp_full_read(int fd, unsigned int *data_len);

#endif

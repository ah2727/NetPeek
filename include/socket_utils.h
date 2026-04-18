#pragma once

int np_socket_set_nonblocking(int fd);
int np_socket_set_cloexec(int fd);
int np_socket_set_reuseaddr(int fd);
int np_socket_set_tcp_nodelay(int fd);
int np_socket_get_error(int fd);
int np_socket_close(int fd);
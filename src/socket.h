ssize_t socket_recv( request* req, void* buf, size_t buf_size);
ssize_t socket_send( request* req, const void* buf, size_t buf_size);
void socket_set_options( int fd);

#ifdef HAVE_TCP_CORK
void socket_flush( int fd);
#else
# define socket_flush( fd) 
#endif

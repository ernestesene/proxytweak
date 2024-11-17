/* returns -1 on err, connect fd on success */
extern int connect_remote_server ();

#ifdef __WIN32__
extern int write_winsock (int fd, const void *buf, unsigned int count);
extern int read_winsock (int fd, void *buf, unsigned int count);
#endif

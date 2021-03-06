#define Eth1_IP "10.0.2.15"
#define PORTNUM "0"
#define PORTLEN 10
#define MAXBUFLEN 100
#define LINELEN 50
#define FNAMELEN 20
#define MAXROUTER 10
#define MAXMSGLEN 100
/*config*/
extern int num_stage;
extern int num_router;
/*router*/
extern int router_sockfd;
extern int router_port;
extern int router_raw_sockfd;
/*proxy*/
extern int proxy_sockfd;
extern int proxy_port;
extern int rec_router_port[MAXROUTER];
extern int tun_fd;

/*read config functions*/
int stage_line(char *sp);
int router_line(char *sp);
int read_config(FILE *fp);
int write_file(char *filename, char *cont);
/*create functions*/
int create_proxy(); 
int create_router();
int create_raw_socket();
int tunnel_create();
int tun_alloc(char *dev, int flags); 
void *get_in_addr(struct sockaddr *sa);
unsigned short get_port(struct sockaddr *sa);
/*communication functions*/
int proxy_udp_reader(char *buffer, int count);
int proxy_udp_sender(int num, char *sendmsg);
int router_udp_reader(char *buffer);
int router_udp_sender(char *sendmsg);//create
int router_udp_sender2(char *sendmsg);
int router_raw_receiver(char *buf);//3
int router_select();//3
int router_raw_sender(char *buf, struct in_addr addr_dst);//3
int tunnel_reader(char *buffer);
int tunnel_write(char *buf);
/*packet manipulation*/
uint16_t ip_checksum(const void *buf, size_t hdr_len);

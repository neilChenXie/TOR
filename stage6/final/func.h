#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <limits.h>
#include <assert.h>
#define Eth0_IP "10.0.2.15"
#define Eth1_IP "192.168.201.2"
#define Eth2_IP "192.168.202.2"
#define Eth3_IP "192.168.203.2"
#define Eth4_IP "192.168.204.2"
#define PORTNUM "0"
#define PORTLEN 10
#define MAXBUFLEN 100
#define LINELEN 100//this maybe not enough for stage 5
#define FNAMELEN 20
#define MAXROUTER 10
#define MAXMSGLEN 100
/*stage 6 AES key*/
extern const int AES_KEY_LENGTH_IN_BITS;
extern const int AES_KEY_LENGTH_IN_CHARS;
typedef struct{
	uint8_t key[16];
}aes_key_t;
/*stage5 payload*/
typedef struct{
	struct ip ip;
	uint8_t type;
	uint16_t circuit_id;
	uint16_t udp_port;
}tormsg_t;
typedef struct{
	uint8_t type;
	uint16_t circuit_id;
	int msg_len;
	char msg[MAXBUFLEN];
}torrely_t;
typedef struct{
	uint16_t in_circuit;
	uint16_t out_circuit;
	uint16_t next_port;
	uint16_t pre_port;
	unsigned char my_key[16];
}router_store;
/*temp*/
extern uint16_t pre_port;
/*config*/
extern int num_stage;
extern int num_router;
extern int num_hop;
/*count*/
extern int count;//for router to know who they are
/*router*/
extern int router_sockfd;
extern int router_port;
extern int router_raw_sockfd;
extern router_store router_cir_info;
/*proxy*/
extern int proxy_sockfd;
extern int proxy_port;
extern uint16_t rec_router_port[MAXROUTER];
extern char router_ip[20];
//extern char rec_router_ip[MAXROUTER][20];
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
int proxy_cir_reader(char *buffer);
int proxy_udp_sender(int num, char *sendmsg);
int router_udp_reader(char *buffer);
int router_cir_reader(char *buffer);
int router_udp_sender(char *sendmsg);//create
int router_udp_sender2(char *sendmsg);
int router_cir_sender(char *sendmsg, uint16_t port);
int router_raw_receiver(char *buf);//3
int router_select();//3
int router_raw_sender(char *buf, struct in_addr addr_dst);//3
int tunnel_reader(char *buffer);
int tunnel_write(char *buf);
/*packet manipulation*/
uint16_t ip_checksum(const void *buf, size_t hdr_len);
int extend_msg_create(tormsg_t *extmsg, uint16_t cirid, uint16_t port);
int reply_msg_create(tormsg_t *extmsg, uint16_t port);
int tor_msg_create(char *srcbuf, char *dstbuf);
int content_msg(uint8_t *dstmsg, char *srcmsg);
/*algorithm*/
int rand_hop(int *group);
int create_aes_key(aes_key_t *aeskey);
/*stage 6*/
int ency_msg_copyin(char *dst, unsigned char *src, int msg_len);
int ency_msg_copyout(unsigned char *dst, char *src, int msg_len);
int port_copyin(uint16_t *dst, unsigned char *src);
int port_copyout(unsigned char *dst, uint16_t *src);
int key_store(unsigned char *dst, unsigned char *src, int msg_len);
int get_eny_msg(uint8_t *dstbuf, unsigned char *srcbuf, int msg_len);
/*aes encrypt*/
void class_AES_set_encrypt_key(unsigned char *key_text, AES_KEY *enc_key);
void class_AES_set_decrypt_key(unsigned char *key_text, AES_KEY *dec_key);
void class_AES_encrypt_with_padding(unsigned char *in, int len, unsigned char **out, int *out_len, AES_KEY *enc_key);
void class_AES_decrypt_with_padding(unsigned char *in, int len, unsigned char **out, int *out_len, AES_KEY *dec_key);

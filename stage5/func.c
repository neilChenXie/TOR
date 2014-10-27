#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include "func.h"
#include <inttypes.h>
#include <time.h>

int tun_fd = -1;
int num_stage = 0;
int num_router = 0;
int num_hop = 0;
int proxy_sockfd=0; 
int proxy_port=0;
int router_sockfd=0;
int router_port=0;
uint16_t rec_router_port[MAXROUTER];

/*stage3*/
int router_raw_sockfd=0;
/********/
/*stage5*/
//char rec_router_ip[MAXROUTER][20];
char router_ip[20];
uint16_t pre_port;
/********/

/***************read file functons*************/
/*return the num of stage*/
int stage_line(char *sp) {
	char *comm = "#";
	char *stage = "stage";
	char *startp;
	//char *sh;

	if (strstr(sp,comm) != NULL) {
		return 0;
	} else {
		if (strstr(sp, stage) != NULL) {
			/*get stage num*/
			startp = strchr(sp, ' ');
			startp++;//point to the num
			return atoi(startp);
		}
		return -1;
	}
}

/*return the num of router*/
int router_line(char *sp) {
	char *comm = "#";
	char *routnum = "num_routers";
	char *startp;
	//char *sh;

	if (strstr(sp,comm) != NULL) {
		return 0;
	} else {
		if (strstr(sp, routnum) != NULL) {
			/*get stage num*/
			startp = strchr(sp, ' ');
			startp++;//point to the num
			return atoi(startp);
		}
		return -1;
	}
}
/*return the num of hops*/
int hop_line(char *sp) {
	char *comm = "#";
	char *hopnum = "minitor_hops";
	char *startp;
	if(strstr(sp,comm) != NULL) {
		return 0;
	} else {
		if(strstr(sp, hopnum) != NULL) {
			startp = strchr(sp,' ');
			startp++;
			return atoi(startp);
		}
		return -1;
	}
}
/*read config*/
int read_config(FILE *fp) {
	char line[LINELEN];
	int rv;
	if (fp == NULL) {
		return -1;
	}
	while(fgets(line, sizeof(line), fp) != NULL &&(num_stage == 0 || num_router == 0 || num_hop == 0)) {
		if (num_stage == 0) {
			rv = stage_line(line);
			if(rv > 0) {
				num_stage = rv;
			}
			continue;
		} else if(num_router == 0) {
			/*num of routers*/
			rv = router_line(line);
			if(rv > 0) {
				num_router = rv;
			}
			continue;
		} else {
			rv = hop_line(line);
			if(rv > 0) {
				if(rv <= num_router) {
					num_hop = rv;
				} else {
					fprintf(stderr, "num of hops is bigger than num of routers\n");
					exit(1);
				}
			}
			continue;
		}
	}
	if(num_stage == 0 || num_router == 0 || num_hop == 0) {
		return -1;
	}
	//printf("stage %d\n", num_stage);
	//printf("num_router %d\n", num_router);
	return 0;
}
/*write to file*/
/*
 *return 0 for sucess
 * */
int write_file(char *filename, char *buffer) {
	FILE *fp;
	if((fp = fopen(filename, "a+"))==NULL) {
		fprintf(stderr,"Cannot open proxy log file\n");
		exit(1);
	} else {
		//if(fseek(fp, 0L, SEEK_END) == -1) {
		//	printf("fseek doesn\'t work");
		//}
		fputs(buffer, fp);
		fclose(fp);
		fp = NULL;
	}
	return 0;
}
/*************************************/

/**************get addrinfo***********/
/*return base on IPv4/IPv6 judgement*/
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/*get port num*/
unsigned short get_port(struct sockaddr *sa) 
{
	if(sa->sa_family == AF_INET) {
		return ntohs(((struct sockaddr_in*)sa)->sin_port);
	}
	return ntohs(((struct sockaddr_in6*)sa)->sin6_port);
}
/*****************************************************************/

/***********************create functions***************************/
/*create a socket for proxy to listen*/
/*
 * return 0 for success, 2 for error
 */
int create_proxy() {
	/*getaddrinfo*/
	struct addrinfo hints, *servinfo, *res;
	struct sockaddr res_addr;
	//struct sockaddr_in *res_out_addr;
	socklen_t addrlen;
	int rv;

	/*set hints for getaddrinfo()*/
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	/*getaddrinfo is used to get crucial info for sock() and bind()*/
	if((rv = getaddrinfo(NULL, "0", &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo:%s\n", gai_strerror(rv));
		exit(1);
	}

	/*loop all result and try to bind one until succeed*/
	for(res = servinfo; res != NULL; res = res->ai_next) {
		proxy_sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if(proxy_sockfd == -1) {
			perror("proxy:socket");
			continue;
		}

		if(bind(proxy_sockfd, res->ai_addr, res->ai_addrlen) == -1) {
			/*cannot bind this socket*/
			close(proxy_sockfd);
			perror("proxy: bind");
			continue;
		}
		/*getsockname after successfully bind socket*/
		addrlen = (socklen_t)sizeof res_addr;
		if((getsockname(proxy_sockfd, &res_addr, &addrlen)) == -1) {
			close(proxy_sockfd);
			perror("proxy:getsockname");
			continue;
		}
		//res_out_addr = (struct sockaddr_in*)&res_addr;
		//proxy_port = ntohs(res_out_addr->sin_port);
		proxy_port = get_port(&res_addr);
		break;
	}
	/*release mem*/
	freeaddrinfo(servinfo);
	/*bind failed*/
	if (res == NULL) {
		fprintf(stderr, "proxy:failed to bind socket\n");
		return 2;
	}
	return 0;
}
/*******************create router*****************/
/*
 * return 0 for success, 2 for error
 */
int create_router() {
	struct addrinfo hints, *routinfo, *res;
	struct sockaddr res_addr;
	//struct sockaddr_in *res_out_addr;
	socklen_t addrlen;
	int rv;

	/*set hints for getaddrinfo()*/
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;
	if((rv = getaddrinfo(NULL, "0", &hints, &routinfo)) != 0) {
		fprintf(stderr, "getaddrinfo:%s\n", gai_strerror(rv));
		return 1;
	}
	/* loop through all the results and make socket*/
	for(res = routinfo; res !=NULL; res = res->ai_next) {
		if ((router_sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) == -1) {
			perror("router: socket");
			continue;
		}
		if(bind(router_sockfd, res->ai_addr, res->ai_addrlen) == -1) {
			/*cannot bind this socket*/
			close(router_sockfd);
			perror("router: bind");
			continue;
		}
		/*getsockname after successfully bind socket*/
		addrlen = (socklen_t)sizeof res_addr;
		if((getsockname(router_sockfd, &res_addr, &addrlen)) == -1) {
			close(router_sockfd);
			perror("router:getsockname");
			continue;
		}
		//res_out_addr = (struct sockaddr_in*)&res_addr;
		//router_port = ntohs(res_out_addr->sin_port);
		router_port = get_port(&res_addr);
		break;
	}
	/*release mem*/
	freeaddrinfo(routinfo);
	/*bind failed*/
	if (res == NULL) {
		fprintf(stderr, "router:failed to bind socket\n");
		return 2;
	}
	return 0;
}
/**********create router raw socket for world communication***********/
/*
 * 0 for success, 2 for error
 * */
int create_raw_socket() {
	int rv;
	struct addrinfo *tuninfo, *res;
	/*router know who they are*/
	/*getaddrinfo()*/
	if(count == 0) {
		sprintf(router_ip, "%s\n", Eth1_IP);
	}
	if(count == 1) {
		sprintf(router_ip, "%s\n", Eth2_IP);
	}
	if(count == 2) {
		sprintf(router_ip, "%s\n", Eth3_IP);
	}
	rv = getaddrinfo(router_ip, NULL, NULL, &tuninfo);
	//rv = getaddrinfo(eth_ip, NULL, NULL, &tuninfo);
	if(rv != 0) {
		fprintf(stderr, "getaddrinfo:%s\n", gai_strerror(rv));
		exit(1);
	}
	/*socket()*/
	for(res = tuninfo; res != NULL; res = res->ai_next) {
		router_raw_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		if(router_raw_sockfd == -1) {
			perror("router:raw_socket");
			continue;
		}
		/*connect socket to eth1*/
		rv = bind(router_raw_sockfd, res->ai_addr, res->ai_addrlen);
		if(rv == -1) {
			close(router_raw_sockfd);
			perror("router:raw_bind");
			continue;
		}
		break;
	}
	/*free temp infomation*/
	freeaddrinfo(tuninfo);
	if (res == NULL) {
		fprintf(stderr, "stage3: router: fail to bind raw socket\n");
		return 2;
	}
	return 0;
}

/********************************************************************/

/*********************communication functions************************/
/*proxy UDP reader*/
int proxy_udp_reader(char *buffer, int count) {
	int numbytes;
	struct sockaddr_storage their_addr;
	socklen_t addr_len;
	//char buf[MAXBUFLEN];
	//char s[INET6_ADDRSTRLEN];

	//printf("proxy: waiting to recvfrom....\n");

	addr_len = sizeof their_addr;

	numbytes = recvfrom(proxy_sockfd, buffer, MAXBUFLEN-1, 0, (struct sockaddr *)&their_addr, &addr_len);

	if(numbytes != -1) {
		//printf("stage1: proxy: got packet from %s\n",
		//		inet_ntop(their_addr.ss_family,
		//			get_in_addr((struct sockaddr *)&their_addr),
		//			s, sizeof s));
		//sprintf(rec_router_ip[count],"%s\n",
		//		inet_ntop(their_addr.ss_family,
		//			get_in_addr((struct sockaddr *)&their_addr),
		//			s, sizeof s));
		//printf("stage1: proxy: packet is %d bytes long\n", numbytes);
		buffer[numbytes] = '\0';
		/*get information of router*/
		rec_router_port[count] = get_port((struct sockaddr *)&their_addr);
	}

	if (numbytes == -1) {
		perror("recvfrom");
		exit(1);
	}
	return 0;
}
/********************proxy_cir_reader**********************/
int proxy_cir_reader(char *buffer) {
	int numbytes;
	struct sockaddr_storage their_addr;
	socklen_t addr_len;
	//char buf[MAXBUFLEN];
	//char s[INET6_ADDRSTRLEN];
	//printf("proxy: waiting to recvfrom....\n");
	addr_len = sizeof their_addr;
	printf("stage5: proxy waiting for done message\n");

	numbytes = recvfrom(proxy_sockfd, buffer, 2*MAXBUFLEN, 0, (struct sockaddr *)&their_addr, &addr_len);
	if(numbytes != -1) {
		//printf("stage1: proxy: got packet from %s\n",
		//		inet_ntop(their_addr.ss_family,
		//			get_in_addr((struct sockaddr *)&their_addr),
		//			s, sizeof s));
		//sprintf(rec_router_ip[count],"%s\n",
		//		inet_ntop(their_addr.ss_family,
		//			get_in_addr((struct sockaddr *)&their_addr),
		//			s, sizeof s));
		//printf("stage1: proxy: packet is %d bytes long\n", numbytes);
		pre_port = get_port((struct sockaddr *)&their_addr);
		buffer[numbytes] = '\0';
		/*get information of router*/
	}
	if (numbytes == -1) {
		perror("recvfrom");
		exit(1);
	}
	return 0;
}
/*router UDP reader*/
int router_udp_reader(char *buffer) {
	int numbytes;
	struct sockaddr_storage their_addr;
	socklen_t addr_len;
	//char src[INET6_ADDRSTRLEN];
	//char dst[INET6_ADDRSTRLEN];
	
	//printf("router: waiting to recvfrom....\n");

	addr_len = sizeof their_addr;
	//printf("router: router_socket:%d\n",router_sockfd);

	numbytes = recvfrom(router_sockfd, buffer, MAXBUFLEN-1, 0, (struct sockaddr *)&their_addr, &addr_len);
	
	if(numbytes != -1) {
		//inet_ntop(their_addr.ss_family,
		//			get_in_addr((struct sockaddr *)&their_addr),
		//			src, sizeof src);
		//printf("router: got packet from %s\n", src);
		//printf("router: packet is %d bytes long\n", numbytes);
		buffer[numbytes] = '\0';
	}
	if(numbytes == -1) {
		perror("recvform");
		exit(1);
	}
	return 0;
}
/*router cir reader*/
int router_cir_reader(char *buffer) {
	int numbytes;
	struct sockaddr_storage their_addr;
	socklen_t addr_len;
	//char src[INET6_ADDRSTRLEN];
	//char dst[INET6_ADDRSTRLEN];
	
	//printf("router: waiting to recvfrom....\n");

	addr_len = sizeof their_addr;
	//printf("router: router_socket:%d\n",router_sockfd);

	numbytes = recvfrom(router_sockfd, buffer, 2*MAXBUFLEN, 0, (struct sockaddr *)&their_addr, &addr_len);
	
	if(numbytes != -1) {
		//inet_ntop(their_addr.ss_family,
		//			get_in_addr((struct sockaddr *)&their_addr),
		//			src, sizeof src);
		//printf("router: got packet from %s\n", src);
		//printf("router: packet is %d bytes long\n", numbytes);
		/**************stage5: get port number************/
		pre_port = get_port((struct sockaddr *)&their_addr);
		/*************************************************/
		buffer[numbytes] = '\0';
	}
	if(numbytes == -1) {
		perror("recvform");
		exit(1);
	}
	return 0;
}
/*router UDP sender*/
int router_udp_sender(char *sendmsg) {
	struct addrinfo hints, *servinfo, *res;
	struct sockaddr res_addr;
	//struct sockaddr_in *res_out_addr;
	socklen_t addrlen;
	//int sendsocket;
	int numbytesent;
	int rv;
	/*change int portnum to char*/
	char proxyport[PORTLEN];
	sprintf(proxyport,"%d",proxy_port);
	printf("stage1: router %d: I will send to port: %s\n", count+1, proxyport);

	/*set hints for getaddrinfo()*/
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;
	/*get proxy info*/
	if((rv = getaddrinfo(NULL, proxyport, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo:%s\n", gai_strerror(rv));
		return 1;
	}
	/*create send socket*/
	for (res = servinfo; res != NULL; res = res->ai_next) {
		//sendsocket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		router_sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (router_sockfd == -1) {
			perror("router:sendsocket");
			continue;
		}
		break;
	}
	if (res == NULL) {
		fprintf(stderr, "router:failed to bind socket\n");
	}
	//res_out_addr = (struct sockaddr_in*)&res_addr;
	//router_port = ntohs(res_out_addr->sin_port);
	/*send infomation*/
	numbytesent = sendto(router_sockfd, sendmsg, strlen(sendmsg), 0, res->ai_addr, res->ai_addrlen);
	if (numbytesent == -1) {
		perror("router:sendto");
		exit(1);
	}
	if((getsockname(router_sockfd, &res_addr, &addrlen)) == -1) {
		close(router_sockfd);
		perror("router:getsockname");
	}
	router_port = get_port(&res_addr);
	freeaddrinfo(servinfo);
	return 0;
}
/**2***/
int router_udp_sender2(char *sendmsg) {
	struct addrinfo hints, *servinfo, *res;
	//struct sockaddr res_addr;
	//struct sockaddr_in *res_out_addr;
	//socklen_t addrlen;
	//int sendsocket;
	int numbytesent;
	int rv;
	/*change int portnum to char*/
	char proxyport[PORTLEN];
	sprintf(proxyport,"%d",proxy_port);
	printf("stage2: router %d: I will send to port: %s\n", count+1, proxyport);

	/*set hints for getaddrinfo()*/
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;
	/*get proxy info*/
	if((rv = getaddrinfo(NULL, proxyport, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo:%s\n", gai_strerror(rv));
		return 1;
	}
	/*create send socket*/
	res = servinfo;
	if (res == NULL) {
		fprintf(stderr, "router:failed to bind socket\n");
		return -1;
	}
	numbytesent = sendto(router_sockfd, sendmsg, 2*MAXBUFLEN, 0, res->ai_addr, res->ai_addrlen);
	if (numbytesent == -1) {
		perror("router:sendto");
		exit(1);
	}
	freeaddrinfo(servinfo);
	return 0;
}
/*************router circuit setup sender***********/
int router_cir_sender(char *sendmsg, uint16_t port) {
	struct addrinfo hints, *servinfo, *res;
	//struct sockaddr res_addr;
	//struct sockaddr_in *res_out_addr;
	//socklen_t addrlen;
	//int sendsocket;
	int numbytesent;
	int rv;
	/*change int portnum to char*/
	char sendport[PORTLEN];
	sprintf(sendport,"%d",port);
	/*set hints for getaddrinfo()*/
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;
	/*get proxy info*/
	if((rv = getaddrinfo(NULL, sendport, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo:%s\n", gai_strerror(rv));
		return 1;
	}
	/*create send socket*/
	res = servinfo;
	if (res == NULL) {
		fprintf(stderr, "router:failed to bind socket\n");
		return -1;
	}
	numbytesent = sendto(router_sockfd, sendmsg, 2*MAXBUFLEN, 0, res->ai_addr, res->ai_addrlen);
	if (numbytesent == -1) {
		perror("router:sendto");
		exit(1);
	}
	freeaddrinfo(servinfo);
	return 0;
}
/**************router raw socket sender*************/
int router_raw_sender(char *buf,struct in_addr addr_dst) {
	struct sockaddr_in receiver_addr;
	struct msghdr msg;
	struct iovec iov;
	int rv;
	/*receiver informantion*/
	receiver_addr.sin_family = AF_INET;
	receiver_addr.sin_addr = addr_dst;//addr of www.csail.mit.edu
	receiver_addr.sin_port = htonl(0);
	msg.msg_name = &receiver_addr;
	msg.msg_namelen = sizeof receiver_addr;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_iov->iov_base = buf;
	msg.msg_iov->iov_len = 64;
	msg.msg_control = 0;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	/*sendmsg*/
	rv = sendmsg(router_raw_sockfd, &msg, 0);
	printf("stage3: router %d: send through raw socket:%d\n", count+1, rv);
	if(rv == -1) {
		fprintf(stderr, "raw socket send failed\n");
		return 2;
	}
	return 0;
}
/************router raw socket receiver**************/
int router_raw_receiver(char *buf) {
	int numbytes;//record bytes received
	struct sockaddr_storage their_addr;//for recvfrom
	socklen_t addr_len;//for recvfrom

	printf("stage3: router %d:waiting to recvfrom raw socket.....\n", count+1);

	addr_len = sizeof their_addr;
	
	numbytes = recvfrom(router_raw_sockfd, buf, MAXBUFLEN-1, 0, (struct sockaddr *)&their_addr, &addr_len);

	if(numbytes != -1) {
		//buf[numbytes] = '\0';
	}
	if(numbytes == -1) {
		perror("router:recvfrom");
		exit(1);
	}
	return 0;
}
/*************router select************************/
int router_select() {
	int maxfd;
	//int nread;
	fd_set readfd;
	
	FD_ZERO(&readfd);
	FD_SET(router_sockfd, &readfd);
	FD_SET(router_raw_sockfd, &readfd);
	
	if(router_sockfd > router_raw_sockfd) {
		maxfd = router_sockfd;
	} else {
		maxfd = router_raw_sockfd;
	}

	/*router wait from eth1 or proxy*/
	printf("stage3: router %d:wait for traffic\n", count+1);
	select(maxfd+1, &readfd, NULL, NULL, NULL);//never timeout
	if(FD_ISSET(router_sockfd, &readfd)) {
		return 2;
	}
	if(FD_ISSET(router_raw_sockfd, &readfd)) {
		return 3;
	}
	/*******/
	return 0;
}
/****************************************************/
/*proxy UDP sender*/
int proxy_udp_sender(int num, char *sendmsg) {
	struct addrinfo hints, *routinfo, *res;
	//struct sockaddr res_addr;
	//struct sockaddr_in *res_out_addr;
	//socklen_t addrlen;
	//int sendsocket;
	int numbytesent;
	int rv;
	/*change int portnum to char*/
	char routport[PORTLEN];
	sprintf(routport,"%d",rec_router_port[num]);

	/*set hints for getaddrinfo()*/
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;
	/*get router info*/
	if((rv = getaddrinfo(NULL, routport, &hints, &routinfo)) != 0) {
		fprintf(stderr, "getaddrinfo:%s\n", gai_strerror(rv));
		return 1;
	}
	/*create sendsocket*/
	res = routinfo;
	//for (res = routinfo; res != NULL; res = res->ai_next) {
	//	sendsocket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	//	if (sendsocket == -1) {
	//		perror("proxy:sendsocket");
	//		continue;
	//	}
	//	break;
	//}
	/*send infomation*/
	//numbytesent = sendto(sendsocket, sendmsg, MAXBUFLEN-1, 0, res->ai_addr, res->ai_addrlen);
	numbytesent = sendto(proxy_sockfd, sendmsg, 2*MAXBUFLEN, 0, res->ai_addr, res->ai_addrlen);
	if (numbytesent == -1) {
		perror("proxy:sendto");
		exit(1);
	}
	freeaddrinfo(routinfo);
	return 0;
}
/********************************************************************/
/***************tunnel related functions***********************/
/*alloc tun*/
/*
 *return fd for success, -1 for error
 * */
int tun_alloc(char *dev, int flags) 
{
    struct ifreq ifr;
    int fd, err;
    char *clonedev = (char*)"/dev/net/tun";

    if( (fd = open(clonedev , O_RDWR)) < 0 ) 
    {
	perror("Opening /dev/net/tun");
	return fd;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags;

    if (*dev) 
    {
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) 
    {
	perror("ioctl(TUNSETIFF)");
	close(fd);
	return err;
    }

    strcpy(dev, ifr.ifr_name);
    return fd;
}
/************************tunnel_create****************************/
int tunnel_create() {
    char tun_name[IFNAMSIZ];
    strcpy(tun_name, "tun1");
    tun_fd = tun_alloc(tun_name, IFF_TUN | IFF_NO_PI); 

    if(tun_fd < 0)
    {
	perror("Open tunnel interface");
	exit(1);
    }
	return 0;
}
/************************tunnel_reader************************/
/*
 * return value for UDP or tunnel
 * */
int tunnel_reader(char *buffer)
{
	/******test field for select()***********/
	int maxfd;
	int nread;
	fd_set readfd;
	//struct timeval timeout;
	struct sockaddr_storage their_addr;
	socklen_t addr_len;
	//char buf[MAXBUFLEN];
	//char s[INET6_ADDRSTRLEN];

	FD_ZERO(&readfd);//reset a fd_set
	FD_SET(proxy_sockfd, &readfd);
	FD_SET(tun_fd, &readfd);

	//timeout.tv_sec = 1;//timeout
	//timeout.tv_usec = 0;
	if(proxy_sockfd > tun_fd) {
		maxfd = proxy_sockfd;
	} else {
		maxfd = tun_fd;
	}

	/*proxy wait from tunnel or router*/
	printf("stage2: proxy: wait for traffic\n");
	select(maxfd+1, &readfd, NULL, NULL, NULL);//never timeout

	if(FD_ISSET(proxy_sockfd, &readfd)) {
		/*read from udp socket*/
		nread = recvfrom(proxy_sockfd, buffer, 2*MAXBUFLEN, 0, (struct sockaddr *)&their_addr, &addr_len);

		if(nread != -1) {
			pre_port = get_port((struct sockaddr *)&their_addr);
			buffer[nread] = '\0';
			//printf("stage2: proxy: got packet from %s\n",
			//		inet_ntop(their_addr.ss_family,
			//			get_in_addr((struct sockaddr *)&their_addr),
			//			s, sizeof s));
			//printf("stage2: proxy: packet is %d bytes long\n", nread);
		} else {
			printf("proxy:cannot get msg from router");
		}
		return 2;
	} 
	if(FD_ISSET(tun_fd, &readfd)) {
		/*read from tunnel*/
		int nread = read(tun_fd,buffer,100*sizeof(buffer));
		if(nread < 0) 
		{
			perror("Reading from tunnel interface");
			close(tun_fd);
			exit(1);
		}
		else
		{
			//printf("stage2: proxy: Read a packet from tunnel, packet length:%d\n", nread);
			buffer[nread] = '\0';
			return 3;
		}
	}
	/***************************************/
	return 0;
}
/*write to tunnel*/
int tunnel_write(char *buf) {
	int nread = write(tun_fd,buf,MAXBUFLEN);
	if (nread == -1) {
		perror("cannot write to tunnel\n");
		close(tun_fd);
		exit(1);
	}
	return 0;
}
/*************************packet manipulation**************************/
/*************calculate ip checksum******************/
uint16_t ip_checksum(const void *buf, size_t hdr_len)
{
	unsigned long sum = 0;
	const uint16_t *ip1;

	ip1 = buf;
	while (hdr_len > 1)
	{
		sum += *ip1++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		hdr_len -= 2;
	}

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return(~sum);
}
/******************extend message create**********************/
int extend_msg_create(tormsg_t *extmsg, uint16_t cirid, uint16_t port) {
	char *local_ip = "127.0.0.1";

	/*modify the ip struct*/
	memset(extmsg, 0, 28);
	inet_pton(AF_INET, local_ip, (void *)&extmsg->ip.ip_dst);
	inet_pton(AF_INET, local_ip, (void *)&extmsg->ip.ip_src);
	extmsg->ip.ip_p = 253;
	/*modify the payload*/
	extmsg->type = 0x52;
	extmsg->circuit_id = cirid;
	extmsg->udp_port = port;
	return 0;
}
/******************reply message create*********************/
int reply_msg_create(tormsg_t *extmsg, uint16_t cir_id) {
	//char *local_ip = "127.0.0.1";

	/*modify the ip struct*/
	//memset(extmsg, 0, 28);
	//inet_pton(AF_INET, local_ip, (void *)&extmsg->ip.ip_dst);
	//inet_pton(AF_INET, local_ip, (void *)&extmsg->ip.ip_src);
	//extmsg->ip.ip_p = 253;
	/*modify the payload*/
	extmsg->type = 0x53;
	extmsg->circuit_id = cir_id;
	//extmsg->udp_port = port;
	return 0;
}
/*****************tor_msg_create****************************/
int tor_msg_create(char *dstbuf, char* srcbuf) {
	int i;
	for(i = 0; i < MAXBUFLEN; i++) {
		*dstbuf = *srcbuf;
		dstbuf++;
		srcbuf++;
	}
	return 0;	
}
/*content_msg*/
int content_msg(uint8_t *dstmsg, char *srcmsg) {
	int i;
	for(i = 0; i < MAXBUFLEN; i++) {
		*dstmsg = *srcmsg & 0xff;
		dstmsg++;
		srcmsg++;
	}
	return 0;
}
/*****************algorithm**********************************/
int rand_hop(int *group) {
	int i;
	int pos_ary[num_router];
	int temp;
	/*initial array*/
	for(i = 0; i < num_router; i++) {
		group[i] = i;
	}
	/*create random pos*/
	for(i = 0; i < num_router; i++) {
		srand((unsigned)time(0));
		pos_ary[i] = rand()%num_router;
	}
	/*swap pos*/
	for(i = 0; i < num_router; i++) {
		temp = group[i];
		group[i] = group[pos_ary[i]];
		group[pos_ary[i]] = temp;
	}
	return 0;
}

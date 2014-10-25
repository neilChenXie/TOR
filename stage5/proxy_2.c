/*
 *proxy.c 
 writen by Chen Xie
Date: 09/24/2014
v0.1
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <fcntl.h>
#include "func.h"


int count = 0;//multi routers
int main(int argc, char *argv[])
{
	FILE *fp=NULL, *proxyfp=NULL, *routfp=NULL;
	char recline[LINELEN];
	char filename[FNAMELEN];
	int fpid;//fork process

	/*check the input*/
	if (argc != 2) {
		fprintf(stderr,"usage:second arguement is file name\n");
		return -1;
	}
	/*****************/

	/*read config file*/
	fp = fopen(argv[1], "r");
	if(fp == NULL) {
		fprintf(stderr,"Cannot open file: %s",argv[1]);
		return -1;
	}
	read_config(fp);
	fclose(fp);
	printf("stage: %d\n",num_stage);
	printf("router: %d\n",num_router);
	/******************/

	/*create proxy*/
	if(create_proxy() != 0) {
		fprintf(stderr,"Cannot create proxy\n");
		return -1;
	}
	printf("proxy_port:%d\n", proxy_port);
	printf("proxy_socket:%d\n",proxy_sockfd);
	/**************/

	/*create proxy log*/
	sprintf(filename, "stage%d.proxy.out",num_stage);
	if((proxyfp = fopen(filename, "w+"))==NULL) {
		fprintf(stderr, "Cannot create proxy log file\n");
		exit(1);
	} else {
	//	if(fseek(proxyfp, 0L, SEEK_END) == -1) { //go to end of log file
	//		printf("fseek doesn\'t work");
	//	}
		sprintf(recline,"stage1\nproxy port:%d\n",proxy_port);
		fputs(recline,proxyfp);
		fclose(proxyfp);
		proxyfp = NULL;
	}
	/***********************************/

	/*fork router process*/
	while(count < num_router) {
		fpid = fork();
		if(fpid != 0) {
			/*waiting for recvfrom*/
			char buffer[MAXBUFLEN];
			if(proxy_udp_reader(buffer, count) != 0) {
				fprintf(stderr, "Cannot get packets from router\n");
			}
			//printf("proxy receive:%s\n", buffer);
			/*record*/
			sprintf(filename, "stage%d.proxy.out", num_stage);
			sprintf(recline, "router: %d, pid %s, port: %d\n", count+1, buffer, rec_router_port[count]);
			if(write_file(filename, recline) != 0) {
				fprintf(stderr, "Cannot write to file: %s\n", filename);
			}
			/**********/
		}
		if(fpid == 0) {
			/*router subroutine*/
			// the count var can let router to know the num of itself
			int pid = getpid();
			char sendmsg[MAXMSGLEN];

			printf("stage1: router:I,m child process: %d\n", pid);
			

			/*send pid to proxy*/
			sprintf(sendmsg,"%d", pid);
			router_udp_sender(sendmsg);
			/*stage 3 create raw socket*/
			create_raw_socket();
			/*get port*/
			printf("router_port:%d\n", router_port);
			printf("router_socket:%d\n", router_sockfd);
			printf("router_raw_socket:%d\n", router_raw_sockfd);
			/*recorde*/
			/*create router log file*/
			sprintf(filename, "stage%d.router%d.out", num_stage,count+1);
			if((routfp = fopen(filename, "w+"))==NULL) {
				fprintf(stderr, "Cannot open/create proxy log file\n");
				exit(1);
			}
			sprintf(recline,"router: %d, pid: %d, port: %d\n", count+1, pid, router_port);
			fputs(recline,routfp);
			fclose(routfp);
			/**************************/
			/*for stage 2 of router*/
			struct ip *ip;
			int hlenl;
			struct icmp *icmp;
			char ipdst[20];
			char ipsrc[20];
			int rv;
			while(1) {
				/*wait ICMP msg from proxy*/
				/*use accept instead*/
				rv = 0;
				rv = router_select();
				/*from proxy*/
				if (rv == 2) {
					char routbuf[MAXBUFLEN];
					router_udp_reader(routbuf);
					//	/*get info in ICMP*/
					ip = (struct ip*) routbuf;
					inet_ntop(AF_INET,(void*)&ip->ip_src,ipsrc,16);
					inet_ntop(AF_INET,(void*)&ip->ip_dst,ipdst,16);
					if(ip->ip_p != IPPROTO_ICMP) {
						fprintf(stderr, "proxy: not ICMP msg from tunne\n");
						exit(1);
					}
					hlenl = ip->ip_hl << 2;
					icmp = (struct icmp*)(routbuf+hlenl);
					/*write to file*/
					sprintf(recline, "ICMP from port:%d, src:%s, dst:%s, type:%d\n", proxy_port, ipsrc, ipdst, icmp->icmp_type);
					write_file(filename, recline);
					///*write a reply to proxy*/
					//icmp->icmp_type = 0;
					//inet_pton(AF_INET, ipdst,(void *)&ip->ip_src);
					//inet_pton(AF_INET, ipsrc,(void *)&ip->ip_dst);
					//router_udp_sender2(routbuf);
					/*******send to eth1**********/
					/*only need to seed ICMP msg*/
					router_raw_sender((char *)icmp, ip->ip_dst);
				}
				/*from eth1*/
				if(rv == 3) {
					printf("stage3: router: receive from eth1\n");
					/*read from eth1*/
					char stage3buf[MAXBUFLEN];
					router_raw_receiver(stage3buf);
					/*analyse the packet*/
					ip = (struct ip*) stage3buf;
					inet_ntop(AF_INET,(void*)&ip->ip_src,ipsrc,16);
					inet_ntop(AF_INET,(void*)&ip->ip_dst,ipdst,16);
					if(ip->ip_p != IPPROTO_ICMP) {
						fprintf(stderr, "proxy: not ICMP msg from eth1\n");
						exit(1);
					}
					hlenl = ip->ip_hl << 2;
					icmp = (struct icmp*)(stage3buf+hlenl);
					/*write to file*/
					sprintf(recline, "ICMP from raw socket, src:%s, dst:%s, type:%d\n", ipsrc, ipdst, icmp->icmp_type);
					write_file(filename, recline);
					/*revise ip header*/
					inet_pton(AF_INET, Eth0_IP, (void *)&ip->ip_dst);
					memset((void *)&ip->ip_sum, 0, sizeof(ip->ip_sum));
					ip->ip_sum = ip_checksum((const void *)ip, hlenl);
					/*send to proxy*/
					router_udp_sender2(stage3buf);

				}
			}
			/***********************/
			exit(0);
		}
		count++;
	}
	/*for stage 2 of proxy*/
	if(tunnel_create() != 0) {
		fprintf(stderr, "proxy:cannot connect to tunnel");
		exit(1);
	}
	while(1) {
		char stage2buf[MAXBUFLEN] = "";
		int rv;
		/*for ICMP msg*/
		struct ip *ip;
		int hlenl;
		struct icmp *icmp;
		char ipdst[20];
		char ipsrc[20];
		
		rv = tunnel_reader(stage2buf);
		printf("rv:%d\n",rv);
		if (rv == 2) {
			//from router
			/*get ICMP msg*/
			ip = (struct ip*) stage2buf;
			inet_ntop(AF_INET,(void*)&ip->ip_src,ipsrc,16);
			inet_ntop(AF_INET,(void*)&ip->ip_dst,ipdst,16);
			if(ip->ip_p != IPPROTO_ICMP) {
				fprintf(stderr, "proxy: not ICMP msg from tunne\n");
				exit(1);
			}
			hlenl = ip->ip_hl << 2;
			icmp = (struct icmp*)(stage2buf+hlenl);
			sprintf(recline,"ICMP from port:%d, src:%s, dst:%s, type:%d\n", rec_router_port[0], ipsrc, ipdst, icmp->icmp_type);
			/*send to tunnel*/
			//printf("proxy: send ICMP ECHO reply to tunnel\n");
			if(tunnel_write(stage2buf) != 0) {
				fprintf(stderr, "proxy:cannot write to tunnel");
				exit(1);
			}
		}
		if (rv == 3) {
			//from tunnel
			/****************test**************/
			int to_send = 0;
			/**********************************/
			/*get ICMP msg*/
			ip = (struct ip*) stage2buf;
			inet_ntop(AF_INET,(void*)&ip->ip_src,ipsrc,16);
			inet_ntop(AF_INET,(void*)&ip->ip_dst,ipdst,16);
			//printf("........ip_dst........: %u\n", ip->ip_dst.s_addr);
			//printf("........ip_dst........: %u\n", ntohl(ip->ip_dst.s_addr));
			//router_to_send = ntohl(ip->ip_dst.s_addr)%num_router;
			//printf("which router to send:%u\n",router_to_send);
			if(ip->ip_p != IPPROTO_ICMP) {
				fprintf(stderr, "proxy: not ICMP msg from tunne\n");
				exit(1);
			}
			hlenl = ip->ip_hl << 2;
			icmp = (struct icmp*)(stage2buf+hlenl);
			//sprintf(recline,"ICMP from tunnel, src:%s, dst:%s, type:%d\n", ipsrc, ipdst,icmp->icmp_type);
			/*send to router*/
			//printf("proxy: send to router with port: %d\n", rec_router_port[0]);
			//which = 0;
			
			to_send = ntohl(ip->ip_dst.s_addr)%num_router;
			printf("which router to send:%d\n",to_send);
			if(proxy_udp_sender(to_send, stage2buf) != 0) {
				fprintf(stderr, "proxy:cannot send ICMP to router");
				exit(1);
			}
			sprintf(recline,"ICMP from tunnel, src:%s, dst:%s, type:%d\n", ipsrc, ipdst,icmp->icmp_type);
		}
		//printf("writein:%s\n",recline);
		sprintf(filename, "stage%d.proxy.out", num_stage);
		if(write_file(filename, recline) != 0) {
			fprintf(stderr, "proxy: cannot write to file");
			exit(1);
		}
	}
	/**********************/
	return 0;
}

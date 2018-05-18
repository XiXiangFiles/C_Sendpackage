#include<stdio.h>
#include<stdlib.h>
#include<iostream>
#include<string.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()

#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_ICMPV6, INET6_ADDRSTRLEN
#include <netinet/ip.h>       // IP_MAXPACKET (which is 65535)
#include <netinet/ip6.h>      // struct ip6_hdr
#include <netinet/icmp6.h>    // struct icmp6_hdr and ICMP6_ECHO_REQUEST
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>
#include <sys/time.h>         // gettimeofday()
#include "Wang-C-C-lib-/Arraylist.cpp"
#include <errno.h>            // errno, perror()
#include<ifaddrs.h>

#define ETH_HDRLEN 14
#define IP6_HDRLEN 40
#define ICMP_HDRLEN 8
class package{
public:
	char *allocate(int len){
		void *ptr;
		if(len>0){
			ptr=malloc(len *sizeof(char));
		}else{
			perror("allocate errot : len < 0");
		}
		return (char *)ptr;
	}
	char *getmac(char **interface){
		
		int status;
		struct ifreq ifr;
		char *mac;
		mac=allocate(sizeof(ifr.ifr_name));
		memset(&ifr,0,sizeof(ifr));
		snprintf(ifr.ifr_name,sizeof(ifr.ifr_name),"%s", *interface);
		if((status=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0){
			perror("Fail to get mac at creat socket.");
			exit(0);
		}
		printf("interface= %s \n",*interface);
		if((ioctl(status,SIOCGIFHWADDR,&ifr))<0){
			perror("failed to get mac addr");
			exit(0);
		}

		memcpy(mac,ifr.ifr_hwaddr.sa_data,sizeof(ifr.ifr_hwaddr.sa_data));	
		return mac;
	}
	ArrayList *ipv6_ip(){
		ArrayList *arr=new ArrayList();

		struct ifaddrs *ifaddr;
		getifaddrs(&ifaddr);
		while(ifaddr!=NULL){
			if(ifaddr->ifa_addr->sa_family!=AF_INET6){
			}else{	
				void *ptr;
				ptr=&((struct sockaddr_in6 *)ifaddr->ifa_addr)->sin6_addr;	
				//char ip6[INET6_ADDRSTRLEN];
				char *ip6;
				ip6=allocate(INET6_ADDRSTRLEN);
				inet_ntop(AF_INET6, ptr ,ip6,INET6_ADDRSTRLEN);//get ip
				arr->put(ip6,INET6_ADDRSTRLEN);
				
			}
			ifaddr=ifaddr->ifa_next;
		}	
		return arr;
	}



};

int main(void){
	package *pak=new package();
	ArrayList listip6= pak->ipv6_ip();
	for(int i=0 ; i< listip6->length(); i++){
		printf("%s\n",listip6->pop());
	}


	return 0;
}
// void send_package(char *s_mac, char *d_mac, char *des_ip , char *sou_ip , char *data);
// uint16_t checksum (uint16_t *, int);
// uint16_t icmp6_checksum (struct ip6_hdr, struct icmp6_hdr, uint8_t *, int);
// int main(int argc, char const *argv[])
// {
// 	/* code */
// 	int send;
// 	char *interface,*source,*destination ,*s_mac ,*d_mac;


// 	destination= allocate(INET6_ADDRSTRLEN);
// 	source=allocate(INET6_ADDRSTRLEN);
// //	device=malloc(sizeof(struct sockaddr_ll));
// 	s_mac=allocate(6);
// 	d_mac=allocate(6);
// 	if(argc<2){
// 		perror("ps1= resource , ps2 =destination ");
// 	}
// 	if((send=socket(PF_PACKET,SOCK_RAW,htons (ETH_P_ALL)))<0){
// 		perror("creat socket failed");
// 	}
// 	strcpy(destination,argv[1]);

	
// 	printf("Source= %s\n",source);
// 	printf("Destination = %s\n",destination);
// 	memcpy(s_mac,getmac(&interface),6);
// 	printf("s_mac= ");
// 	for(int i=0;i<6;i++){
// 		printf("%2x",s_mac[i]);
// 		d_mac[i]=0xff;
// 	}
// 	char *data="test";

// 	send_package(s_mac,d_mac, destination , source ,data);


// 	return 0;
// }




// void  send_package(char *s_mac, char *d_mac, char *des_ip , char *sou_ip,char *data){
// 	int status,frame_length;
// 	struct sockaddr_ll device;
// 	struct ip6_hdr send_iphdr;
// 	struct icmp6_hdr send_icmphdr;
// 	uint8_t *send_ether_frame;
	
// 	device.sll_family=AF_PACKET;
// //	memcpy(device.sll_addr,s_mac ,6);
// 	device.sll_halen=htons(6);


// 	send_iphdr.ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);
// 	send_iphdr.ip6_plen = htons (ICMP_HDRLEN + strlen(data));
// 	send_iphdr.ip6_nxt = IPPROTO_ICMPV6;
// 	send_iphdr.ip6_hops = 255;
// 	if((status=inet_pton(AF_INET6,sou_ip,&(send_iphdr.ip6_src)))<0){
// 		perror("inet_pton() Error!");
// 	}
// 	if((status=inet_pton(AF_INET6,des_ip,&(send_iphdr.ip6_dst)))<0){
// 		perror("inet_pton() Error!");
// 	}

// 	send_icmphdr.icmp6_type =200;
// 	send_icmphdr.icmp6_code = 0;
// 	send_icmphdr.icmp6_id = htons (1000);
// 	send_icmphdr.icmp6_seq = htons (0);
// 	send_icmphdr.icmp6_cksum = 0;
// //	send_icmphdr.icmp6_cksum = icmp6_checksum (send_iphdr, send_icmphdr, data, strlen(data));
// 	frame_length = 6 + 6 + 2 + IP6_HDRLEN + ICMP_HDRLEN + strlen(data);
// //	memcpy (send_ether_frame, d_mac, 6 * sizeof (uint8_t));
// //	memcpy (send_ether_frame + 6, s_mac, 6 * sizeof (uint8_t));
// 	send_ether_frame[12] = ETH_P_IPV6 / 256;
// 	send_ether_frame[13] = ETH_P_IPV6 % 256;
// }

// uint16_t icmp6_checksum (struct ip6_hdr iphdr, struct icmp6_hdr icmp6hdr, uint8_t *payload, int payloadlen)
// {
//   char buf[IP_MAXPACKET];
//   char *ptr;
//   int chksumlen = 0;
//   int i;

//   ptr = &buf[0];  // ptr points to beginning of buffer buf

//   // Copy source IP address into buf (128 bits)
//   memcpy (ptr, &iphdr.ip6_src.s6_addr, sizeof (iphdr.ip6_src.s6_addr));
//   ptr += sizeof (iphdr.ip6_src);
//   chksumlen += sizeof (iphdr.ip6_src);

//   // Copy destination IP address into buf (128 bits)
//   memcpy (ptr, &iphdr.ip6_dst.s6_addr, sizeof (iphdr.ip6_dst.s6_addr));
//   ptr += sizeof (iphdr.ip6_dst.s6_addr);
//   chksumlen += sizeof (iphdr.ip6_dst.s6_addr);

//   // Copy Upper Layer Packet length into buf (32 bits).
//   // Should not be greater than 65535 (i.e., 2 bytes).
//   *ptr = 0; ptr++;
//   *ptr = 0; ptr++;
//   *ptr = (ICMP_HDRLEN + payloadlen) / 256;
//   ptr++;
//   *ptr = (ICMP_HDRLEN + payloadlen) % 256;
//   ptr++;
//   chksumlen += 4;

//   // Copy zero field to buf (24 bits)
//   *ptr = 0; ptr++;
//   *ptr = 0; ptr++;
//   *ptr = 0; ptr++;
//   chksumlen += 3;

//   // Copy next header field to buf (8 bits)
//   memcpy (ptr, &iphdr.ip6_nxt, sizeof (iphdr.ip6_nxt));
//   ptr += sizeof (iphdr.ip6_nxt);
//   chksumlen += sizeof (iphdr.ip6_nxt);

//   // Copy ICMPv6 type to buf (8 bits)
//   memcpy (ptr, &icmp6hdr.icmp6_type, sizeof (icmp6hdr.icmp6_type));
//   ptr += sizeof (icmp6hdr.icmp6_type);
//   chksumlen += sizeof (icmp6hdr.icmp6_type);

//   // Copy ICMPv6 code to buf (8 bits)
//   memcpy (ptr, &icmp6hdr.icmp6_code, sizeof (icmp6hdr.icmp6_code));
//   ptr += sizeof (icmp6hdr.icmp6_code);
//   chksumlen += sizeof (icmp6hdr.icmp6_code);

//   // Copy ICMPv6 ID to buf (16 bits)
//   memcpy (ptr, &icmp6hdr.icmp6_id, sizeof (icmp6hdr.icmp6_id));
//   ptr += sizeof (icmp6hdr.icmp6_id);
//   chksumlen += sizeof (icmp6hdr.icmp6_id);

//   // Copy ICMPv6 sequence number to buff (16 bits)
//   memcpy (ptr, &icmp6hdr.icmp6_seq, sizeof (icmp6hdr.icmp6_seq));
//   ptr += sizeof (icmp6hdr.icmp6_seq);
//   chksumlen += sizeof (icmp6hdr.icmp6_seq);

//   // Copy ICMPv6 checksum to buf (16 bits)
//   // Zero, since we don't know it yet.
//   *ptr = 0; ptr++;
//   *ptr = 0; ptr++;
//   chksumlen += 2;

//   // Copy ICMPv6 payload to buf
//   memcpy (ptr, payload, payloadlen * sizeof (uint8_t));
//   ptr += payloadlen;
//   chksumlen += payloadlen;

//   // Pad to the next 16-bit boundary
//   for (i=0; i<payloadlen%2; i++, ptr++) {
//     *ptr = 0;
//     ptr += 1;
//     chksumlen += 1;
//   }

//   return checksum ((uint16_t *) buf, chksumlen);
// }
// uint16_t checksum (uint16_t *addr, int len)
// {
//   int nleft = len;
//   int sum = 0;
//   uint16_t *w = addr;
//   uint16_t answer = 0;

//   while (nleft > 1) {
//     sum += *w++;
//     nleft -= sizeof (uint16_t);
//   }

//   if (nleft == 1) {
//     *(uint8_t *) (&answer) = *(uint8_t *) w;
//     sum += answer;
//   }

//   sum = (sum >> 16) + (sum & 0xFFFF);
//   sum += (sum >> 16);
//   answer = ~sum;
//   return (answer);
// }

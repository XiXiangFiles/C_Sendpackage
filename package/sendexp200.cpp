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

typedef struct ip6_hdr Ip6Hdr;
typedef struct icmp6_hdr Icmp6Hdr;
typedef struct sockaddr_ll sockaddr_ll;

class package{
	private:

		uint8_t *send_ether_frame=(uint8_t *) malloc (IP_MAXPACKET * sizeof (uint8_t));
	public:
		void printfhex(char *str,int num){
			for(int i=0; i<num ;i++){
				if(str[i]!= 0){
					printf("%x",str[i]);
				}
			}
			printf("\n");
		}
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
			printf("getmac (interface=%s)\n",*interface);
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
		uint16_t checksum (uint16_t *addr, int len){
			int nleft = len;
	  		int sum = 0;
	  		uint16_t *w = addr;
	  		uint16_t answer = 0;

   			while (nleft > 1) {
		    	sum += *w++;
		    	nleft -= sizeof (uint16_t);
		  	}

			if (nleft == 1) {
				*(uint8_t *) (&answer) = *(uint8_t *) w;
				sum += answer;
			}

			sum = (sum >> 16) + (sum & 0xFFFF);
			sum += (sum >> 16);
			answer = ~sum;
			return (answer);
		}
		uint16_t icmp6_checksum (struct ip6_hdr iphdr, struct icmp6_hdr icmp6hdr, uint8_t *payload, int payloadlen){
  			char buf[IP_MAXPACKET];
  			char *ptr;
			int chksumlen = 0;
			int i;

  			ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (128 bits)
  			memcpy (ptr, &iphdr.ip6_src.s6_addr, sizeof (iphdr.ip6_src.s6_addr));
  			ptr += sizeof (iphdr.ip6_src);
  			chksumlen += sizeof (iphdr.ip6_src);

  // Copy destination IP address into buf (128 bits)
  			memcpy (ptr, &iphdr.ip6_dst.s6_addr, sizeof (iphdr.ip6_dst.s6_addr));
  			ptr += sizeof (iphdr.ip6_dst.s6_addr);
  			chksumlen += sizeof (iphdr.ip6_dst.s6_addr);

  // Copy Upper Layer Packet length into buf (32 bits).
  // Should not be greater than 65535 (i.e., 2 bytes).
			*ptr = 0; ptr++;
			*ptr = 0; ptr++;
			*ptr = (ICMP_HDRLEN + payloadlen) / 256;
			ptr++;
			*ptr = (ICMP_HDRLEN + payloadlen) % 256;
			ptr++;
			chksumlen += 4;

			  // Copy zero field to buf (24 bits)
			*ptr = 0; ptr++;
			*ptr = 0; ptr++;
			*ptr = 0; ptr++;
			chksumlen += 3;
			// Copy next header field to buf (8 bits)
			memcpy (ptr, &iphdr.ip6_nxt, sizeof (iphdr.ip6_nxt));
			ptr += sizeof (iphdr.ip6_nxt);
			chksumlen += sizeof (iphdr.ip6_nxt);
			// Copy ICMPv6 type to buf (8 bits)
			memcpy (ptr, &icmp6hdr.icmp6_type, sizeof (icmp6hdr.icmp6_type));
			ptr += sizeof (icmp6hdr.icmp6_type);
			chksumlen += sizeof (icmp6hdr.icmp6_type);
			// Copy ICMPv6 code to buf (8 bits)
			memcpy (ptr, &icmp6hdr.icmp6_code, sizeof (icmp6hdr.icmp6_code));
			ptr += sizeof (icmp6hdr.icmp6_code);
			chksumlen += sizeof (icmp6hdr.icmp6_code);
			// Copy ICMPv6 ID to buf (16 bits)
			memcpy (ptr, &icmp6hdr.icmp6_id, sizeof (icmp6hdr.icmp6_id));
			ptr += sizeof (icmp6hdr.icmp6_id);
			chksumlen += sizeof (icmp6hdr.icmp6_id);
			// Copy ICMPv6 sequence number to buff (16 bits)
			memcpy (ptr, &icmp6hdr.icmp6_seq, sizeof (icmp6hdr.icmp6_seq));
			ptr += sizeof (icmp6hdr.icmp6_seq);
			chksumlen += sizeof (icmp6hdr.icmp6_seq);
			 // Copy ICMPv6 checksum to buf (16 bits)
			  // Zero, since we don't know it yet.
			*ptr = 0; ptr++;
			*ptr = 0; ptr++;
			chksumlen += 2;
			// Copy ICMPv6 payload to buf
			memcpy (ptr, payload, payloadlen * sizeof (uint8_t));
			ptr += payloadlen;
			chksumlen += payloadlen;
			 // Pad to the next 16-bit boundary
			for (i=0; i<payloadlen%2; i++, ptr++) {
			*ptr = 0;
			ptr += 1;
			chksumlen += 1;
		}
	}
	Ip6Hdr creat_IPv6Header(char *dest_mac, char *sour_mac , char *src_ip, char *dest_ip,int datalen){
	 	
		int status;
		Ip6Hdr send_iphdr;
		send_iphdr.ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);
		send_iphdr.ip6_plen = htons (ICMP_HDRLEN + datalen);
		send_iphdr.ip6_nxt = IPPROTO_ICMPV6;
		send_iphdr.ip6_hops = 255;
	
		if ((status = inet_pton (AF_INET6, src_ip, &(send_iphdr.ip6_src))) != 1) {
    		fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    		exit (EXIT_FAILURE);
  		}

  		if ((status = inet_pton (AF_INET6, src_ip, &(send_iphdr.ip6_dst))) != 1) {
    		fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    		exit (EXIT_FAILURE);
  		}
  		return send_iphdr;
		
	}
	icmp6_hdr creat_Icmphdr(int icmp6_type, int icmp6_code , Ip6Hdr send_iphdr  ,char *data){
		Icmp6Hdr send_icmphdr;
		send_icmphdr.icmp6_type =icmp6_type;
		send_icmphdr.icmp6_code = icmp6_code;
		send_icmphdr.icmp6_id = htons (1000);
		send_icmphdr.icmp6_seq = htons (0);
// ICMP header checksum (16 bits): set to 0 when calculating checksum
  		send_icmphdr.icmp6_cksum = 0;
		send_icmphdr.icmp6_cksum = icmp6_checksum (send_iphdr, send_icmphdr, (uint8_t *)data, strlen(data));
		return send_icmphdr;
	}
	uint8_t *creat_send_ether_frame(char *dst_mac,char *src_mac,Ip6Hdr send_iphdr,Icmp6Hdr send_icmphdr,char *data){
		
		//uint8_t send_ether_frame[IP_MAXPACKET];
		memcpy(send_ether_frame,dst_mac,6);
		memcpy(send_ether_frame+6,src_mac,6);
		send_ether_frame[12] = ETH_P_IPV6 / 256;
  		send_ether_frame[13] = ETH_P_IPV6 % 256;
  		memcpy(send_ether_frame+ETH_HDRLEN,&send_iphdr,IP6_HDRLEN*sizeof(uint8_t));
  		memcpy (send_ether_frame + ETH_HDRLEN + IP6_HDRLEN, &send_icmphdr, ICMP_HDRLEN * sizeof (uint8_t));
  		memcpy (send_ether_frame + ETH_HDRLEN + IP6_HDRLEN + ICMP_HDRLEN, data, strlen(data) * sizeof (uint8_t));

  		return send_ether_frame;

	}
	sockaddr_ll fill_sockaddr(char * interface, char * src_mac){
		sockaddr_ll device;
		
		if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
			exit (EXIT_FAILURE);
  		}
  		printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);
		device.sll_family = AF_PACKET;
		memcpy (device.sll_addr, src_mac, 6 * sizeof (uint8_t));
	 	device.sll_halen = htons (6);

		return device;
	
	}
	int sendpak(uint8_t *send_ether_frame,struct sockaddr_ll device ,int frame_length){
		int send,status;
		if((send=socket(PF_PACKET, SOCK_RAW, htons (ETH_P_ALL)))<0){
			perror("error to creat rawsocket");
		}
		
		if (( status = sendto (send, &send_ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
	     	perror ("sendto() failed ");
	      	exit (EXIT_FAILURE);
    	}
		
		return 0;
	}
	void check_frame(uint8_t *package ,int start, int end){
		for(int i=start;i<end ; i++){
			printf("%x",package[i]);
			if((i%100)==0){
				printf("\n");
			}
		}
		printf("\n");
	}
};
int main(void){
	char *dest_mac,*sour_mac,*ip;
	char *interface="wlan0";
	sockaddr_ll device;
	package *pak=new package();
	uint8_t *send_ether_frame=(uint8_t*)malloc(sizeof(uint8_t)*IP_MAXPACKET);

//-------------------------------allocate memory for mac address String  
	dest_mac=pak->allocate(6);
	sour_mac=pak->allocate(6);
//	pak->getmac(&interface);
	memcpy(sour_mac,pak->getmac(&interface),6);
	
	dest_mac[0]=0xff;	
	dest_mac[1]=0xff;	
	dest_mac[2]=0xff;
	dest_mac[3]=0xff;
	dest_mac[4]=0xff;	
	dest_mac[5]=0xff;

	ArrayList *listip6=new ArrayList(); 
	listip6=pak->ipv6_ip();
	for(int i=0 ; i< listip6->length(); i++){
		char *str= listip6->pop();
		if(strstr(str,"bbbb")){
			ip=(char *)malloc(sizeof(char) * INET6_ADDRSTRLEN);
			ip=str;
//			printf("%s\n",ip);
		//	memcpy(ip,str,INET6_ADDRSTRLEN);
		}
	//	printf("ip6[%d]=%s\n",i,listip6->pop());
	}
//	pak->printfhex(sour_mac,6);
	
	char *data="WongWong Test";
	
	Ip6Hdr ipv6_header=pak->creat_IPv6Header(dest_mac,sour_mac,ip,"bbbb::100",strlen(data));
	printf("send_iphdr=%x\n",ipv6_header.ip6_plen ); 
	icmp6_hdr icmp6hdr=pak->creat_Icmphdr(200, 0 , ipv6_header  ,data);
	printf( "%d\n",icmp6hdr.icmp6_type);

	send_ether_frame=pak->creat_send_ether_frame(dest_mac,sour_mac ,ipv6_header,icmp6hdr,data);
//	printf("test ip6hdr hops=%d",ipv6_header->ip6_hops);	

//	device=pak->fill_sockaddr(sour_mac,interface);

//	int frame_length = 6 + 6 + 2 + IP6_HDRLEN + ICMP_HDRLEN + strlen(data);
	
	pak->check_frame(send_ether_frame,0,100 );
	printf("test \n");
//	while(true){
	//	pak->sendpak(send_ether_frame,device,frame_length);
//	}	
	

	return 0;
}



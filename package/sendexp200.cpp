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



};

int main(void){
	char *dest_mac,*sour_mac;
	char *interface="wlan0";
	package *pak=new package();

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
		printf("ip6[%d]=%s\n",i,listip6->pop());
	}
	pak->printfhex(sour_mac,6);

	return 0;
}



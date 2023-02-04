// run_without_root (do on shell) : setcap cap_net_raw+ep executable_file
/**		snet-ping.c : tools untuk cek koneksi melalui socket
 * 		created by : Jaya Wikrama
 * 		edited by : Ergi & Khalid
 * 		copyright (c) Delameta Bilano 2020
 * 
 */


#include <stdio.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "shiki-net-tools.h"

#define PACKET_SIZE 64  
#define PORT_NO 0 
#define PING_DELAY 1000000
#define REQUEST_TIMEOUT 2

#define INFO "INFO:"
#define WARNING "WARNING:"
#define CRITICAL "CRITICAL:"

static unsigned short checksum(void *b, int len);
static int my_ping_init(char *address, struct sockaddr_in *address_conf, char *ip_address);
static int send_ping(int my_sock_for_ping, struct sockaddr_in *ping_address, char *ping_ip, int ping_num);


struct ping_pkt 
{ 
	struct icmphdr hdr; 
	char msg[PACKET_SIZE-sizeof(struct icmphdr)]; 
};


static unsigned short checksum(void *b, int len){
	unsigned short *buff = b;
	unsigned int sum=0;
	unsigned short result;

	for ( sum = 0; len > 1; len -= 2 ) 
		sum += *buff++; 
	if ( len == 1 ) 
		sum += *(unsigned char*)buff; 
	sum = (sum >> 16) + (sum & 0xFFFF); 
	sum += (sum >> 16); 
	result = ~sum; 
	return result; 
} 

static int my_ping_init(char *address, struct sockaddr_in *address_conf, char *ip_address){
	int my_retval = 0;	
	struct hostent *my_host;

	if ((my_host = gethostbyname(address)) == NULL) 
	{
		my_net_debug(__func__, CRITICAL, "FAILED TO GET HOST BY NAME!");
		my_retval = -1;
	}
	else {
		(*address_conf).sin_port = htons (PORT_NO);
		(*address_conf).sin_family = my_host->h_addrtype;
		(*address_conf).sin_addr.s_addr = *(long*)my_host->h_addr;
		strcpy(ip_address, inet_ntoa(*(struct in_addr *)my_host->h_addr));
	}
	return my_retval;
}

static int send_ping(int my_sock_for_ping, struct sockaddr_in *ping_address, char *ping_ip, int ping_num){
	struct ping_pkt pckt;
	struct sockaddr_in r_addr;
	struct timeval tv_out;
	struct timespec tm_start, tm_end;
	int retval = 0;
	int ttl_val=64, msg_count=0, i;
	socklen_t addr_len;	
	long double total_tm_ping;

	tv_out.tv_sec = REQUEST_TIMEOUT;
	tv_out.tv_usec = 0;

	if (setsockopt(my_sock_for_ping, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0) 
	{
		/** Jika ada error di socket, make socket di close.
		 * 
		 */ 
		close(my_sock_for_ping);
		my_net_debug(__func__, INFO, "Socket CLOSED");
		my_net_debug(__func__, CRITICAL, "Setting socket options to TTL failed!");
	}
	else
	{
		//my_net_debug(__func__, INFO, "Socket set to TTL");
	}

	// setting timeout of recv setting
	setsockopt(my_sock_for_ping, SOL_SOCKET, SO_RCVTIMEO,(const char*)&tv_out, sizeof tv_out);

	while (msg_count < ping_num){
		memset(&pckt, 0x00, sizeof(pckt));
		pckt.hdr.type = ICMP_ECHO;
		pckt.hdr.un.echo.id = getpid();
		
		for ( i = 0; i < sizeof(pckt.msg)-1; i++ ) pckt.msg[i] = i+'0'; 
		
		pckt.msg[i] = 0; 
		pckt.hdr.un.echo.sequence = msg_count++; 
		pckt.hdr.checksum = checksum(&pckt, sizeof(pckt)); 
		addr_len=sizeof(r_addr);

		//send packet
		clock_gettime(CLOCK_MONOTONIC, &tm_start);
		if (sendto(my_sock_for_ping, &pckt, sizeof(pckt), 0, (struct sockaddr*) ping_address, sizeof(*ping_address)) <= 0) 
		{ 
			/** Jika ada error di socket, make socket di close.
			 * 
			 */ 
			close(my_sock_for_ping);
			my_net_debug(__func__, INFO, "Socket CLOSED");
			my_net_debug(__func__, CRITICAL, "Packet Sending Failed!"); 
			retval = -1; 
		} 
		//receive packet
		else if (recvfrom(my_sock_for_ping, &pckt, sizeof(pckt), 0, (struct sockaddr*)&r_addr, &addr_len) <= 0 && msg_count>1) 
		{ 
			/** Jika ada error di socket, make socket di close.
			 * 
			 */ 
			close(my_sock_for_ping);
			my_net_debug(__func__, INFO, "Socket CLOSED");
			my_net_debug(__func__, CRITICAL, "Packet receive failed!");
			retval = -2;
		}
		else {
			clock_gettime(CLOCK_MONOTONIC, &tm_end);
			total_tm_ping = (tm_end.tv_sec - tm_start.tv_sec)*1000.0;
			total_tm_ping = total_tm_ping + (tm_end.tv_nsec - tm_start.tv_nsec)/1000000.0;

			if(!(pckt.hdr.type==69 && pckt.hdr.code==0))
			{
				my_net_debug(__func__, WARNING, "Packet received %s with ICMP type ? code ?", ping_ip);
				retval = 0;
			}
			else
			{
				my_net_debug(__func__, INFO, "%d bytes from (%s) msg_seq=%d ttl=%d rtt = %Lf ms", PACKET_SIZE, ping_ip, msg_count, ttl_val, total_tm_ping);
				if (retval == 0) retval = (int)total_tm_ping;
				else retval = (retval + (int)total_tm_ping)/2;
			}
		}
		if (msg_count < ping_num) usleep(PING_DELAY);
	}
	/** Selesai memakai socket, socket di close.
	 * 
	 */ 
	close(my_sock_for_ping);	
	my_net_debug(__func__, INFO, "Socket CLOSED");

	return retval;
}

int snet_ping(char *_address, int _num_of_ping){
	int sockfd; 
	char ip_addr[16]; 
	struct sockaddr_in addr_con;
	
	if(my_ping_init(_address, &addr_con, ip_addr) == -1) 
	{ 
		my_net_debug(__func__, CRITICAL, "DNS lookup failed! Could not resolve hostname!");
		return -1;
	}

	//my_net_debug(__func__, INFO, "Trying to connect to '%s' IP: %s", _address, ip_addr); 

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); 
	if(sockfd<0) 
	{ 
		my_net_debug(__func__, CRITICAL, "Socket file descriptor not received!!"); 
		return -1; 
	} 
	else{
		//my_net_debug(__func__, INFO, "ping start...");
	}
	int retval = send_ping(sockfd, &addr_con, ip_addr, _num_of_ping);
	return retval;
}

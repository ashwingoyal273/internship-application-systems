// C program to Implement Ping 

// compile as -o ping 
// run as sudo ./ping <hostname> 

#include <stdio.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netdb.h> 
#include <unistd.h> 
#include <string.h> 
#include <stdlib.h> 
#include <netinet/ip_icmp.h> 
#include <time.h> 
#include <fcntl.h> 
#include <signal.h> 
#include <time.h> 

// Define the Packet Constants 
// ping packet size 
#define PING_PKT_S 64 

// Automatic port number 
#define PORT_NO 0 

#define PING_SLEEP_RATE 1000000

// Gives the timeout delay for receiving packets 
// in seconds 
#define RECV_TIMEOUT 1 

// Define the Ping Loop 
int pingloop=1; 


// ping packet structure 
struct ping_pkt 
{ 
	struct icmphdr hdr; 
	char msg[PING_PKT_S-sizeof(struct icmphdr)]; 
}; 

// Calculating the Check Sum 
unsigned short checksum(void *b, int len) 
{ 
	unsigned short *buf = b; 
	unsigned int sum=0; 
	unsigned short result; 

	for ( sum = 0; len > 1; len -= 2 ) 
		sum += *buf++; 
	if ( len == 1 ) 
		sum += *(unsigned char*)buf; 
	sum = (sum >> 16) + (sum & 0xFFFF); 
	sum += (sum >> 16); 
	result = ~sum; 
	return result; 
} 


// Interrupt handler 
void intHandler(int dummy) 
{ 
	pingloop=0; 
} 

struct sockaddr* dns_lookup_adv(char *addr_host, char* ip_addr)
{
	struct addrinfo hints, *res, *p;
	int err;

	 memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	err = getaddrinfo(addr_host, "http", &hints, &res);
    if(err != 0) {
        printf("ERR: %s\n", gai_strerror(err));
        return NULL;
    }

    void *addr;
    struct sockaddr_in *ipv4;
    struct sockaddr_in6 *ipv6;
    char ipstr[INET6_ADDRSTRLEN];

    for(p = res ;p != NULL; p = p->ai_next) {

        // ipv4
        if(p->ai_family == AF_INET) {
            // convert generic addr to internet addr
            ipv4 = (struct sockaddr_in *)p->ai_addr;

            // point to binary addr for convert to str later
            addr = &(ipv4->sin_addr);

        // ipv6
        } else {
            // convert generic addr to internet addr
            ipv6 = (struct sockaddr_in6 *)p->ai_addr;

            // point to binary addr for convert to str later
            addr = &(ipv6->sin6_addr);
        }

        // convert binary addr to str
        inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
      	break;

    }

    // don't forget to free the addrinfo
    freeaddrinfo(res);
    strcpy(ip_addr, ipstr);
    return p->ai_addr;



}

// make a ping request 
void send_ping(int ping_sockfd, struct sockaddr *ping_addr, 
				char *ping_dom, char *ping_ip, int ttl_val) 
{ 
	int msg_count=0, i, addr_len, flag=1, msg_received_count=0;
	struct ping_pkt pckt; 
	struct sockaddr r_addr; 
	struct timespec time_start, time_end, tfs, tfe; 
	long double rtt_msec=0, total_msec=0; 
	struct timeval tv_out; 
	tv_out.tv_sec = RECV_TIMEOUT; 
	tv_out.tv_usec = 0; 

	clock_gettime(CLOCK_MONOTONIC, &tfs); 

	// setting timeout of recv setting 
	setsockopt(ping_sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_out, sizeof tv_out); 

	// send icmp packet in an infinite loop 
	while(pingloop) 
	{ 
		// flag is whether packet was sent or not 
		flag=1; 
	
		//filling packet 
		bzero(&pckt, sizeof(pckt)); 
		
		pckt.hdr.type = ICMP_ECHO; 
		pckt.hdr.un.echo.id = getpid(); 
		
		for ( i = 0; i < sizeof(pckt.msg)-1; i++ ) 
			pckt.msg[i] = i+'0'; 
		
		pckt.msg[i] = 0; 
		pckt.hdr.un.echo.sequence = msg_count++; 
		pckt.hdr.checksum = checksum(&pckt, sizeof(pckt)); 


		usleep(PING_SLEEP_RATE); 

		//send packet 
		clock_gettime(CLOCK_MONOTONIC, &time_start); 
		if (sendto(ping_sockfd, &pckt, sizeof(pckt), 0, ping_addr, sizeof(*ping_addr)) <= 0) 
		{ 
			printf("\nPacket Sending Failed!\n\n"); 
			flag=0; 
		} 

		//receive packet 
		addr_len=sizeof(r_addr); 

		if (recvfrom(ping_sockfd, &pckt, sizeof(pckt), 0, &r_addr, &addr_len) <= 0 && msg_count >= 1) 
		{ 
			printf("\nPacket receive failed!\n\n"); 
		} 

		else
		{ 
			clock_gettime(CLOCK_MONOTONIC, &time_end); 
			
			double timeElapsed = ((double)(time_end.tv_nsec - time_start.tv_nsec))/1000000.0;
			rtt_msec = (time_end.tv_sec- time_start.tv_sec) * 1000.0 + timeElapsed; 
			
			if(flag) 
			{ 
				if(!(pckt.hdr.type ==69 && pckt.hdr.code==0)) 
				{ 
					printf("Error..Packet received with ICMP type %d code %d\n", pckt.hdr.type, pckt.hdr.code); 
					if(pckt.hdr.code == 192)
						printf("Time Limit Exceeded!\n\n");
				} 
				else
				{ 
						printf("%d bytes from %s (%s) msg_seq=%d ttl=%d rtt = %Lf ms.\n", PING_PKT_S, ping_dom, ping_ip, msg_count, ttl_val, rtt_msec); 
						msg_received_count++; 
				} 
			} 
		}	 
	} 
	clock_gettime(CLOCK_MONOTONIC, &tfe); 
	double timeElapsed = ((double)(tfe.tv_nsec - tfs.tv_nsec))/1000000.0; 
	
	total_msec = (tfe.tv_sec-tfs.tv_sec)*1000.0 + timeElapsed;
	double percent_packet_loss = (double)(msg_count-msg_received_count)*100/msg_count;
					
	printf("\n===%s ping statistics===\n", ping_ip); 
	printf("\n%d packets sent, %d packets received, %.6g percent packet loss. Total time: %Lf ms.\n\n", msg_count, msg_received_count, percent_packet_loss, total_msec); 
} 

// Driver Code 
int main(int argc, char *argv[]) 
{ 
	int ttl_val = 64;

	if(argc!=2 && argc!= 3) 
	{ 
		printf("\nUsage: %s <address> <TTL(optional - defaults to 64)>\n", argv[0]); 
		return 0; 
	} 

	if(argc == 3)
	{
		ttl_val = atoi(argv[2]);
		if(ttl_val == 0)
		{
			printf("TTL Value entered invalid! Defaulting to 64\n");
			ttl_val = 64;
		}
		else
		{
			printf("Custom TTL Value entered! TTL: %d\n", ttl_val);
		}
	}

	struct sockaddr* addr;
	char ip_addr[256];
	addr = dns_lookup_adv(argv[1], ip_addr);
	if(addr->sa_family == AF_INET)
	{
		int sockfd;
		sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
			if(sockfd<0) 
			{ 
				printf("\nSocket file descriptor not received!!\n"); 
				return 0; 
			} 
			else
				printf("\nSocket file descriptor %d received\n", sockfd);
		
		printf("IM IN IPV4 CODE\n");

		if (setsockopt(sockfd, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0) 
		{ 
			perror("lol");
			printf("\nSetting socket options to TTL failed!\n"); 
			return 0; 
		} 
		else
		{ 
			printf("\nSocket set to TTL..\n"); 
		} 

		signal(SIGINT, intHandler);

		send_ping(sockfd, addr, argv[1], ip_addr, ttl_val); 
		}
	else
	{
		int sockfd;
		sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
			if(sockfd<0) 
			{ 
				printf("\nSocket file descriptor not received!!\n"); 
				return 0; 
			} 
			else
				printf("\nSocket file descriptor %d received\n", sockfd);
		printf("IM IN IPV6 CODE\n");

		if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl_val, sizeof(ttl_val)) != 0) 
		{ 
			printf("\nSetting socket options to TTL failed!\n"); 
			return 0; 
		} 

		else
		{ 
			printf("\nSocket set to TTL..\n"); 
		} 

		signal(SIGINT, intHandler);

		send_ping(sockfd, addr, argv[1], ip_addr, ttl_val);
	}
	
	return 0; 
} 


#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h>
#include<stdlib.h> 
#include<string.h> 
#include<netinet/ip_icmp.h>  
#include<netinet/udp.h>
#include<netinet/tcp.h> 
#include<netinet/ip.h>  
#include<netinet/if_ether.h> 
#include<net/ethernet.h>
#include<net/if.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include <time.h>
#include <unistd.h>
#include <errno.h> 
#include <limits.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>

#define true 0
#define false 1
#define bool int
#define PKTSIZE 65536
#define RELEASE_TIME 50

int chr2int(const char * chr) {
	int num;
	char *p;
	errno = 0;
	long conv = strtol(chr, &p, 10);

	if (errno != 0 || *p != '\0' || conv > INT_MAX) {
		printf("Wrong format of port\n");
		exit(1);
	} else {
		num = conv;    
		return num;
	}
}

double timer() {
	double time_in_mill;
	struct timeval  tv;
	gettimeofday(&tv, NULL);
	time_in_mill = (tv.tv_sec) * 1000 + (tv.tv_usec) / 1000;
	return time_in_mill;
}

int main( int argc, const char* argv[]) {
	if(argc != 5) {	
		printf("Wrong number of arguments needs 3\n");
		exit(0);
	}
	bool release = true;
	const char *key = argv[1];
	int port = chr2int(argv[2]);
	const char *ipaddr = argv[3];
	const char *iface = argv[4];
	char *hex;
	int nbpkt = 0;
	double t1=0;
	double t2=0;
	int loop = 0;
	hex = (char*)malloc(PKTSIZE);
	char* eth_head = (char*)malloc(25);
	char* hexpks = (char*)malloc(PKTSIZE);
	strcpy(hexpks, "null");
	struct ifreq ifr;
	int saddr_size , data_size, ret;
    struct sockaddr saddr;
    unsigned char *buffer = (unsigned char *) malloc(PKTSIZE);
	int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
	if(sock_raw < 0) {
        //Print the error with proper message
        printf("Socket Error\n");
       	exit(3);
    }	
	int nb = 0;
//START CLIENT SIDE
	struct sockaddr_in server_info;
    struct hostent *he;
	int socket_fd;
	int num = 0;
    char* bufferc = (char *)malloc(PKTSIZE);
	char* buffc = (char *)malloc(PKTSIZE);
	char* buffh = (char *)malloc(PKTSIZE);
    if ((he = gethostbyname(ipaddr))==NULL) {
        printf("Cannot get host name\n");
        exit(4);
    }

    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0))== -1) {
        printf("Socket Failure!!\n");
        exit(5);
    }
	memset(&server_info, 0, sizeof(server_info));
    server_info.sin_family = AF_INET;
    server_info.sin_port = htons(port);
    server_info.sin_addr = *((struct in_addr *)he->h_addr);
    if (connect(socket_fd, (struct sockaddr *)&server_info, sizeof(struct sockaddr))<0) {
        printf("Connection Failure\n");
        exit(6);
    }
	strcpy(bufferc,"[n]sniffer");
	send(socket_fd, bufferc, strlen(bufferc),0);
	sleep(1);
	strcpy(buffc,"c");
	if ((send(socket_fd, "c", 1, 0))== -1) {
            printf("Failure Sending Message\n");
            close(socket_fd);
			close(sock_raw);
            exit(7);
    } else {
        ;//printf("Message being sent: %s\n",bufferc);
    }
    while(( strcmp((const char*)buffc, "q") != true )) {
		if(release == true){
			t2 = timer();
			num = recv(socket_fd, buffc, PKTSIZE, 0);
			release = false;
			if (num == -1) {
		        printf("Error in receiving message!!\n");
		        break;
		    }else if(( !strcmp((const char*)buffc, "c") )) {
				;//printf("Message received: %s\nNumber of bytes received: %d\n", buffc, num);
			}   
			if(( strcmp((const char*)buffc, "q") == true )){
				break;
			}
		}
		num = 0;
		do
		{
		//END CLIENT SIDE
			saddr_size = sizeof saddr;
			data_size = recvfrom(sock_raw , buffer , PKTSIZE , 0 , &saddr , (socklen_t*)&saddr_size);
			if (data_size > 25){
				for(int i=0;i<12;i++){
					char temp[2];
					ret = sprintf(temp, "%02X", buffer[i]);
					eth_head[i*2] = temp[0];
					eth_head[i*2+1] = temp[1];
				}
			}
		} while(strcmp("000000000000000000000000", (const char*)eth_head) == true);
		if (data_size > 25){
			int i;
			hex = (char *) realloc(hex, (data_size)*2+1+1+3);
			strcpy(hex, "{^}");

			for(i=0;i<data_size;i++)
			{
				char temp[2];
				ret = sprintf(temp, "%02X", buffer[i]);
				hex[i*2+3] = temp[0];
				hex[i*2+1+3] = temp[1];
			}

			hex[i*2+1+1+1] = '\0';
			strcpy(buffh, hex);
			strcat(buffh, ";");
			if(strcmp((const char*)hexpks, "null")==true){
				hexpks = (char *) realloc(hexpks, (data_size)*2+1+1+3);
				strcpy(hexpks, buffh);
			}else{
				int len = (int)(strlen(hexpks) + (data_size)*2+1+1+3);
				hexpks = (char *) realloc(hexpks, len);
				strcat(hexpks, buffh);
			}
			t1 = timer();
			if(t1-t2 > RELEASE_TIME){
				release = true;
			}

			if(release == true){
				if((send(socket_fd, hexpks, strlen(hexpks), 0)) == -1){
					break;					
				}
				strcpy(hexpks, "null");
			}
			nbpkt++;
		}
    }
	const char *str = "!q\033[91mSnipet sniffer shutdown\033[0m";
	bufferc = (char *)realloc(bufferc, strlen(str)+1);
	strcpy(bufferc, str);
	send(socket_fd, bufferc, strlen(bufferc), 0);
	free(hex);
	free(eth_head);
	free(buffer);
	free(bufferc);
	free(buffc);
	close(socket_fd);
	close(sock_raw);
    //printf("+--+  FIN DU SNIF  +--+\n");
    return 0;
}

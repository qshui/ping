/**
 *ping程序
 */
 
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdio.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <setjmp.h>
#include <errno.h>
#include <sys/time.h>
#include<signal.h>	
#define PACKET_SIZE 4096
#define ERROR  0
#define SUCCESS 1

int nsent = 0;				//发包序列号		 		
int nrecv = 0;				//收包序列号
struct sockaddr_in dest;	//被ping的主机地址
int sockfd;
struct sigaction act_int;   // 中断信号
struct sigaction act_alarm; //时间信号

void set_sighandler();
void int_handler(int sig);
void alarm_handler(int signo);

/*设置的时间是一个结构体，倒计时设置，重复倒时，超时值设为1秒*/
struct itimerval val_alarm={
							.it_interval.tv_sec = 1,	
                            .it_interval.tv_usec=0,
                            .it_value.tv_sec=0,
                            .it_value.tv_usec=1
                           };

void tv_sub(struct timeval* out, struct timeval *in)
{
	if((out->tv_usec -= in->tv_usec) < 0)
	{
		--out->tv_sec;
		out->tv_usec += 100000;
	}
	out->tv_sec -= in->tv_sec;
}

//校验算法
unsigned short cal_chksum(unsigned short *addr, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;
	while(nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}
	if(nleft == 1)
	{
		*(unsigned char*)(&answer) = *(unsigned char*)w;
		sum += answer;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return answer;
}

int unpack(char *buf, int len, struct sockaddr_in* pfrom)
{
	int i, iphdrlen;
	struct ip *ip;
	struct icmp* icmp;
	struct timeval* tvsend;
	struct timeval tvrecv;
	double time;
	char *from_ip;
	char *dest_ip;
	gettimeofday(&tvrecv, NULL);
	ip = (struct ip*)buf;
	iphdrlen = ip->ip_hl << 2;
	icmp = (struct icmp*)(buf + iphdrlen);
	len -= iphdrlen;
	if(len < 8)
	{
		printf("ICMP packets length is less than 8\n");
		return -1;
	}
	from_ip = (char*)inet_ntoa(pfrom->sin_addr);
	dest_ip = (char*)inet_ntoa(dest.sin_addr);
	if(strcmp(from_ip, dest_ip))
	{
		return -1;
	}
	if((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == getpid()))  
	{
		tvsend = (struct timeval*)icmp->icmp_data;
		tv_sub(&tvrecv, tvsend);
		time = (&tvrecv)->tv_sec * 1000 + (&tvrecv)->tv_usec/1000;
        printf("%d byte from %s: icmp_seq=%u ttl=%d rtt=%.3f ms\n",
            len,
            inet_ntoa(pfrom->sin_addr),
            icmp->icmp_seq,
            ip->ip_ttl,
			time);
	}
	else
	{
		return -1;
	}
	return 0;
}

//组包函数
int pack(char *sendpacket)
{
	int packsize;
	int datalen = 56;
	struct icmp *picmp;
	struct timeval *tval;
	picmp = (struct icmp*)sendpacket;
	picmp->icmp_type = ICMP_ECHO;
	picmp->icmp_code = 0;
	picmp->icmp_cksum = 0;
	picmp->icmp_seq = nsent++;
	picmp->icmp_id = getpid();
	packsize = 8 + datalen;
	tval = (struct timeval *)picmp->icmp_data;
	gettimeofday(tval, NULL);
	picmp->icmp_cksum = cal_chksum((unsigned short *)picmp, packsize);
	return packsize;
}

//ping函数
int ping()
{

	struct timeval *tval;
	int packsize;
	char sendpacket[PACKET_SIZE];
	int n;
	memset(sendpacket, 0, sizeof(sendpacket));
	packsize = pack(sendpacket);
	n = sendto(sockfd, (char *)&sendpacket, packsize, 0, (struct sockaddr *)&dest, sizeof(dest));
	if(n < 1)
	{
		return ERROR;
	}
	return SUCCESS;
}

void recv_reply()
{
	char recvpacket[PACKET_SIZE];
	struct sockaddr_in from;
	socklen_t fromlen;
	int n;
	while(nrecv < 10)
	{
		memset(recvpacket, 0, sizeof(recvpacket));
		fromlen = sizeof(from);
		if((n = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0, (struct sockaddr *)&from, &fromlen)) < 0)
		{
			if(errno==EINTR)
				continue;
		}
		if(unpack(recvpacket, n, &from))
		{
			continue;
		}
		nrecv++;
	}	
}

/*统计ping命令的检测结果*/
void get_statistics(int nsent,int nrecv, const char* destIP)
{
    printf("--- %s ping statistics ---\n", destIP); //被ping主机的IP
    printf("%d packets transmitted, %d received, %0.0f%% ""packet loss\n",
           nsent,nrecv,1.0*(nsent-nrecv)/nsent*100);
}

int main(int argc, char** argv)
{
	struct hostent *host; 
	struct timeval time0;
    if((host=gethostbyname(argv[1]))==NULL)
	{	
		perror("can not understand the host name"); 
		exit(1);
    }
	memset(&dest,0,sizeof dest);	
    dest.sin_family=PF_INET;	
    dest.sin_port=ntohs(0);
    dest.sin_addr=*(struct in_addr *)host->h_addr_list[0];	
	if(argc < 2)
	{
		printf("usage: %s hostname/ip address\n", argv[0]);
		exit(1);
	}
	
	
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(sockfd < 0)
	{
		return ERROR;
	}
	int timeout = 10;
	time0.tv_sec = timeout / 1000;
	time0.tv_usec = timeout % 1000;
	if(setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &time0, sizeof(time0)) == -1)
	{
		return ERROR;
	}	
	set_sighandler();
	if( (setitimer(ITIMER_REAL,&val_alarm,NULL)) == -1 )	
		printf("setitimer fails.");
	recv_reply();
	get_statistics(nsent, nrecv, argv[1]);
	return 0;
}

/*发送CTRL-C程序*/
/*SIGINT（中断信号）处理程序*/
void int_handler(int sig)
{
	char * dest_ip = (char*)inet_ntoa(dest.sin_addr);
    get_statistics(nsent,nrecv, dest_ip);	
    close(sockfd);	
    exit(1);
}

/*SIGALRM（终止进程）处理程序*/
void alarm_handler(int signo)
{
    ping();
}

/*设置信号处理程序*/
void set_sighandler()
{
     act_alarm.sa_handler=alarm_handler;
     if(sigaction(SIGALRM,&act_alarm,NULL)==-1)	
		 printf("SIGALRM handler setting fails.");
    act_int.sa_handler=int_handler;
    if(sigaction(SIGINT,&act_int,NULL)==-1)
        printf("SIGINT handler setting fails.");
}




























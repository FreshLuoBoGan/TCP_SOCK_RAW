#include <sys/socket.h>
#include<netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>    //有tcp包头的定义信息
#include <netinet/ip.h>     //有IP包头的定义信息
#include <netinet/udp.h>     //有UDP包头的定义信息
#include <stdio.h>
#include <string.h>

#define SOU_PORT 789
#define DES_PORT 897

/* 用于计算TCP校验和的伪头部 */  
struct psdhdr{  
    uint32_t saddr; /* ip头部源地址 */  
    uint32_t daddr; /* ip头部目的地址 */  
    uint8_t mbz; /* 补全字段，需为0 */  
    uint8_t protocol; /* ip头部协议 */  
    uint16_t tcpl; /* tcp长度，包括头部和数据部分 */  
};  

/* 
 * 计算校验和 
 * @param[in]: buffer, 待计算数据指针 
 * @param[in]: size, 数据长度 
 * 
 * @return 校验和 
 * */  
uint16_t csum(uint16_t *buffer, int size)  
{  
    unsigned long cksum = 0;  
  
    while(size>1)  
    {  
        cksum += *buffer++;  
        size -= sizeof(uint16_t);  
    }  
  
    if(size)  
    {  
        cksum += *(unsigned char*)buffer;  
    }  
  
    cksum = (cksum>>16) + (cksum&0xffff);  
    cksum += (cksum>>16);   
      
    return (uint16_t)(~cksum);  
} 



#pragma pack(push)
#pragma pack(1)
typedef struct _ip_header                       //定义IP首部 
{ 
    unsigned char ih_verlen;                    //4位首部长度+4位IP版本号 
    unsigned char ih_tos;                       //8位服务类型TOS 服务类型（Type of Service）：长度8比特。8位 按位被如下定义 PPP DTRC0
                                                    // PPP：定义包的优先级，取值越大数据越重要
                                                    // 000 普通 (Routine)
                                                    // 001 优先的 (Priority)
                                                    // 010 立即的发送 (Immediate)
                                                    // 011 闪电式的 (Flash)
                                                    // 100 比闪电还闪电式的 (Flash Override)
                                                    // 101 CRI/TIC/ECP(找不到这个词的翻译)
                                                    // 110 网间控制 (Internetwork Control)
                                                    // 111 网络控制 (Network Control)

                                                    // D 时延: 0:普通 1:延迟尽量小
                                                    // T 吞吐量: 0:普通 1:流量尽量大
                                                    // R 可靠性: 0:普通 1:可靠性尽量大
                                                    // M 传输成本: 0:普通 1:成本尽量小
                                                    // 0 最后一位被保留，恒定为0
    unsigned short ih_total_len;                //16位总长度（字节） 
    unsigned short ih_ident;                    //16位标识 
    unsigned short ih_frag_and_flags;           //3位标志位 
    unsigned char ih_ttl;                       //8位生存时间 TTL 
    unsigned char ih_proto;                     //8位协议 (TCP, UDP 或其他) 
    unsigned short ih_checksum;                 //16位IP首部校验和 
    unsigned int ih_sourceIP;                   //32位源IP地址 
    unsigned int ih_destIP;                     //32位目的IP地址 
}IP_HEADER; 
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
typedef struct _udp_header                       //定义UDP首部
{
    unsigned short uh_sport;                    //16位源端口
    unsigned short uh_dport;                    //16位目的端口
    unsigned int uh_len;                        //16位UDP包长度
    unsigned int uh_sum;                        //16位校验和
}UDP_HEADER;
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
typedef struct _tcp_header                       //定义TCP首部 
{ 
    unsigned short th_sport;                    //16位源端口 
    unsigned short th_dport;                    //16位目的端口 
    unsigned int th_seq;                        //32位序列号 
    unsigned int th_ack;                        //32位确认号 
    unsigned char th_lenres;                    //4位首部长度/6位保留字 
    unsigned char th_flag;                      //6位标志位
    unsigned short th_win;                      //16位窗口大小
    unsigned short th_sum;                      //16位校验和
    unsigned short th_urp;                      //16位紧急数据偏移量
}TCP_HEADER; 
#pragma pack(pop)

//char psdheader[52] = {0};
int main()
{


    int socket_fd = 0;
    int optval = 1;  
    const int *poptval = &optval;  

    IP_HEADER *ip_h;
    TCP_HEADER *tcp_h;

    struct sockaddr_in saddr;
    struct sockaddr_in daddr;
    struct sockaddr_in addrServ;
    struct sockaddr_in client_addr;

    char psdheader[52] = {0};
    char IP_TCP_Packet[80] = {0};
    char Recv_IP_TCP_Packet[80] = {0};

    memset(&daddr,0,sizeof(sockaddr_in));
    memset(&addrServ,0,sizeof(sockaddr_in));
    memset(&client_addr,0,sizeof(sockaddr_in));
    
    ip_h = (IP_HEADER *)(IP_TCP_Packet);
    tcp_h = (TCP_HEADER *)(IP_TCP_Packet + sizeof(IP_HEADER));
    struct psdhdr *psdh = (struct psdhdr*)psdheader;  
    struct tcphdr *tcph_psd = (struct tcphdr*)(psdheader + sizeof(struct psdhdr));  


    inet_pton(AF_INET, (char *)("192.168.101.132"), (void*)&saddr.sin_addr);
    //inet_pton(AF_INET, (char *)("127.0.0.1"), (void*)&saddr.sin_addr);
    saddr.sin_port = htons(SOU_PORT);    
    inet_pton(AF_INET, (char * )("192.168.101.193"), (void*)&daddr.sin_addr);  
    //inet_pton(AF_INET, (char * )("127.0.0.1"), (void*)&daddr.sin_addr);
    daddr.sin_port = htons(DES_PORT);   

    ip_h->ih_verlen = 0b01000101;                          //ipv:4(0100),header len：20×8/（8*4）(0101)
    ip_h->ih_tos = 0;
    ip_h->ih_total_len = sizeof(IP_HEADER) + sizeof(TCP_HEADER);
    ip_h->ih_ident = htons(54321);                       //??
    ip_h->ih_frag_and_flags = htons(0x02 << 13);         //??
    ip_h->ih_ttl = 64;
    ip_h->ih_proto = IPPROTO_TCP;
    ip_h->ih_checksum = 0;
    ip_h->ih_sourceIP = saddr.sin_addr.s_addr;
    ip_h->ih_destIP = daddr.sin_addr.s_addr;
    //pstIpHdr->check = htons(ip_fast_csum((unsigned char *)pstIpHdr, pstIpHdr->ihl));

    tcp_h->th_sport = saddr.sin_port;
    tcp_h->th_dport = daddr.sin_port;
    tcp_h->th_seq   = htonl(111);
    tcp_h->th_ack   = 0;
    tcp_h->th_lenres = (sizeof(TCP_HEADER)/4)<<4;          //??
    tcp_h->th_flag  = TH_SYN;
    tcp_h->th_win  = htons(65535);;
    tcp_h->th_sum  = 0;
    tcp_h->th_urp  = 0;


    psdh->saddr = ip_h->ih_sourceIP;  
    psdh->daddr = ip_h->ih_destIP;  
    psdh->mbz = 0;  
    psdh->protocol = ip_h->ih_proto ;  
    psdh->tcpl = htons(sizeof(struct tcphdr));  
    //data_dump(psdheader, sizeof(struct psdhdr));   
  
    memcpy(tcph_psd, tcp_h, sizeof(TCP_HEADER));  
      
    tcp_h->th_sum = csum((uint16_t*)psdheader, sizeof(struct psdhdr) + sizeof(struct tcphdr));  

    socket_fd = socket(AF_INET,SOCK_RAW,IPPROTO_TCP);

    addrServ.sin_addr.s_addr= htonl(INADDR_ANY);//daddr.sin_addr.s_addr;//指定0.0.0.0地址，表示任意地址
	addrServ.sin_family = AF_INET;//表示IPv4的套接字类型
	addrServ.sin_port = htons(DES_PORT);
	bind(socket_fd, (sockaddr*)&addrServ, sizeof(addrServ));

    if(setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, poptval, sizeof(optval)) < 0)  
    {  
        perror("setsockopt failed!");  
    }

    for(int i = 0;i< ip_h->ih_total_len;i++)
    {
        printf("%x ",IP_TCP_Packet[i]);
    }
    printf("\n");
    
    sendto(socket_fd, IP_TCP_Packet, ip_h->ih_total_len, 0, (struct sockaddr*)&(daddr), sizeof(daddr));  
//    if(ret < 0)  
   // {  
    perror("sendto socket failed!");  
    //    goto err_out;  
    //}    

    socklen_t addrlen = sizeof(client_addr);
    int ret = recvfrom(socket_fd, Recv_IP_TCP_Packet, sizeof(Recv_IP_TCP_Packet), 0,(struct sockaddr *)&client_addr, &addrlen);

    if(ret < 0)  
    {  
        perror("recvfrom socket failed!");   
    }  

    for(int i = 0;i< ret;i++)
    {
        printf("%x ",Recv_IP_TCP_Packet[i]);
    }
    printf("\n");
    ip_h = (IP_HEADER *)(Recv_IP_TCP_Packet);
    tcp_h = (TCP_HEADER *)(Recv_IP_TCP_Packet + sizeof(IP_HEADER));

    printf("%x,%x\n",ntohl(tcp_h->th_ack),ntohl(tcp_h->th_seq));
    int tmp = ntohl(tcp_h->th_seq);
    int tmp2 = ntohl(tcp_h->th_ack);


    ip_h = (IP_HEADER *)(IP_TCP_Packet);
    tcp_h = (TCP_HEADER *)(IP_TCP_Packet + sizeof(IP_HEADER));

    tcp_h->th_seq = htonl(tmp2 +1 );
    tcp_h->th_flag = TH_ACK;
    tcp_h->th_ack = htonl(tmp +1 );
    
    printf("%x\n",tcp_h->th_ack);

    psdh->saddr = ip_h->ih_sourceIP;  
    psdh->daddr = ip_h->ih_destIP;  
    psdh->mbz = 0;  
    psdh->protocol = ip_h->ih_proto ;  
    psdh->tcpl = htons(sizeof(struct tcphdr));  
    //data_dump(psdheader, sizeof(struct psdhdr));   
  
    memcpy(tcph_psd, tcp_h, sizeof(TCP_HEADER));  
      
    tcp_h->th_sum = csum((uint16_t*)psdheader, sizeof(struct psdhdr) + sizeof(struct tcphdr)); 

    sendto(socket_fd, IP_TCP_Packet, ip_h->ih_total_len, 0, (struct sockaddr*)&(daddr), sizeof(daddr));   

    perror("sendto socket failed!");  

        for(int i = 0;i< ip_h->ih_total_len;i++)
    {
        printf("%x ",IP_TCP_Packet[i]);
    }
    printf("\n");
    return 0;
}
#include <sys/socket.h>
#include<netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>    //有tcp包头的定义信息
#include <netinet/ip.h>     //有IP包头的定义信息
#include <netinet/udp.h>     //有UDP包头的定义信息
#include <stdio.h>
#include <string.h>
#include <unistd.h>//usleep
//#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>

#pragma pack(push)
#pragma pack(1)
typedef struct _arp_header //28
{
    short Hardware_type;    //2
    short protocol_type;    //2
    char Hardware_size;     //1
    char protocol_size;     //1
    short Opcode;           //2
    char Send_Mac[6];       //6
    int Send_IP;            //4
    char Target_MAC[6];     //6
    int Target_IP;          //4
}Arp_header;
#pragma pack(pop)

// typedef struct _EthernetII_header
// {
//     char Target_MAC[6];
//     char Send_Mac[6];
//     short protocol;
// }EthernetII_header;

#pragma pack(push)
#pragma pack(1)
 typedef struct {
         struct ethhdr  eth_header;  //struct defined in linux/if_ether.h 14
         Arp_header arp_header;
         char padding[18];
}ARPPACKET;
#pragma pack(pop)

int main()
{
    int on =1;
    int socket_fd = 0;
    char recv_buf[1024];
    char send_buf[60];
    struct sockaddr_in addr;
    // EthernetII_header *E_header;
    // arp_header *a_header;
    ARPPACKET arp_packet;

    // E_header = (EthernetII_header *)send_buf;
    // a_header = (arp_header *)(send_buf + sizeof(EthernetII_header));
    
    memset((&arp_packet.eth_header.h_dest[0]),0xff,sizeof(arp_packet.eth_header.h_dest));
    memset((&arp_packet.arp_header.Target_MAC[0]),0x0,sizeof(arp_packet.eth_header.h_dest));
    arp_packet.eth_header.h_source[0] = 0x00;
    arp_packet.eth_header.h_source[1] = 0x21;
    arp_packet.eth_header.h_source[2] = 0xcc;
    arp_packet.arp_header.Send_Mac[3] = 0xc9;
    arp_packet.eth_header.h_source[4] = 0x2e;
    arp_packet.eth_header.h_source[5] = 0xf0;


    arp_packet.eth_header.h_proto = htons(ETH_P_ARP);

    arp_packet.arp_header.Hardware_type = htons(1);
    arp_packet.arp_header.protocol_type = htons(0x0800);
    arp_packet.arp_header.Hardware_size = 6;
    arp_packet.arp_header.protocol_size = 4;
    arp_packet.arp_header.Opcode  = htons(1);
    arp_packet.arp_header.Send_Mac[0] = 0x00;
    arp_packet.arp_header.Send_Mac[1] = 0x21;
    arp_packet.arp_header.Send_Mac[2] = 0xcc;
    arp_packet.arp_header.Send_Mac[3] = 0xc9;
    arp_packet.arp_header.Send_Mac[4] = 0x2e;
    arp_packet.arp_header.Send_Mac[5] = 0xf0;


    inet_pton(AF_INET, (char *)("192.168.101.254"), (void*)&addr.sin_addr);
    arp_packet.arp_header.Send_IP = addr.sin_addr.s_addr;
    inet_pton(AF_INET, (char *)("192.168.101.193"), (void*)&addr.sin_addr);
    arp_packet.arp_header.Target_IP = addr.sin_addr.s_addr;

    //socket_fd = socket(PF_PACKET,SOCK_DGRAM,htons(ETH_P_ARP));//获取到的包，没有Ethernet II；
    socket_fd = socket(PF_INET,SOCK_PACKET,htons(ETH_P_ARP));//获取到的包，有Ethernet II；
    if(-1 == socket_fd)
    {
        perror("socket_fd");
        while(1);
    }  
    setsockopt(socket_fd,SOL_SOCKET,SO_BROADCAST,&on,sizeof(on));


    while(1)
    {

        struct sockaddr to,from;
        socklen_t fromlen=0;
        strcpy(to.sa_data,"enp0s25");
        int n =  sendto(socket_fd,&arp_packet,sizeof( ARPPACKET),0,&to,sizeof(struct sockaddr));
        //recvfrom(socket_fd,recv_buf,1024,0,&from,&fromlen);
        //int n = send(socket_fd,(char *)&arp_packet,sizeof(ARPPACKET),0);
        printf("%d\n",n);
        if(n == -1)
        {
            perror("n");
            //while(1);
        }
        for(int i = 0;i< n;i++)
        {
            printf("%x ",((char *)(&arp_packet))[i]);
        }
        printf("\n");


        //usleep(1*1000*1000);
    }

}
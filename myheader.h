#ifndef __MYHEADER_H__
#define __MYHEADER_H__

#include <netinet/in.h>
#include <sys/types.h>

struct ethheader {
    u_char  ether_dhost[6]; 
    u_char  ether_shost[6]; 
    u_short ether_type;     
};
struct ipheader {
    unsigned char      iph_ihl:4,  
                        iph_ver:4; 
    unsigned char      iph_tos;    
    unsigned short int iph_len;    
    unsigned short int iph_ident;  
    unsigned short int iph_flag:3, 
                        iph_offset:13; 
    unsigned char       iph_ttl;   
    unsigned char       iph_protocol; 
    unsigned short int  iph_chksum; 
    struct  in_addr     iph_sourceip; 
    struct  in_addr     iph_destip;   
};

struct tcpheader {
    unsigned short int th_sport;   
    unsigned short int th_dport;   
    unsigned int        th_seq;    
    unsigned int        th_ack;    
    unsigned char       th_offx2;  
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    unsigned char       th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
    unsigned short int  th_win;    
    unsigned short int  th_sum;    
    unsigned short int  th_urp;    
};

#endif

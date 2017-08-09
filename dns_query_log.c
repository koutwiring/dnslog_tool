#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <pcap.h> //pcapライブラリ

#include <netinet/in.h>
#include <netinet/if_ether.h> //ethernetヘッダの定義
#include <netinet/ip.h> //ipヘッダの定義
#ifndef __FAVOR_BSD
# define __FAVOR_BSD
#endif
#include <netinet/tcp.h> //tcpヘッダの定義
#include <netinet/udp.h> //udpヘッダの定義

#define MAX_SIZE 2000

void packet_pro(u_char *usr, const struct pcap_pkthdr *header, const u_char *packet);
void udp_head(u_char *packet, struct ip *iph);
void tcp_head(u_char *packet, struct ip *iph);
void q_section(u_char *packet);//DNS question seqtion
u_char *frag_ip_check(u_char *packet, struct ip *iph);

typedef struct list{
	//memory for devision
	u_char *packet;
	u_int p_size;
	char sip[20];
	struct list *next;
}d_list;
d_list *top = NULL;

d_list *set_d_list(u_char *plus_pac, u_int p_size, char *sip, d_list *p);
d_list *insert_d_list(u_char *plus_pac, u_int p_size, char *sip);
d_list *find_d_list(char *sip);
void init_d_list(d_list *mem_p);

pcap_t *pd; //pcap ディスクリプタ

char date[27] = "0000-00-00 00:00:00.000000";
char sip[16] = "000.000.000.000";
char dip[16] = "000.000.000.000";
char proto[4] = "udp";
char domain[MAX_SIZE];

void print_5_pac(u_char *packet){
	int i;
	for(i=0; i<5; i++)
		printf("%02X:", packet[i]);
}

int main(int argc, char const *argv[])
{
	char ebuf[PCAP_ERRBUF_SIZE]; //pcap初期化時のエラーメッセ―ジ格納
	struct bpf_program fp;
	bpf_u_int32 net;
	//dump-XXXXXXXXXXXX
	if (argc != 3) {
		printf("usage:reqpassivedns <pcap file> <DNS server IP which you set>\n");
		return 0;
	}

	char filter_exp[] = "src port not domain and dst port domain and dst host '192.168.000.000' and src host not '192.168.000.000'";
	sprintf(filter_exp, "src port not domain and dst port domain and src host not %s and dst host %s", argv[2], argv[2]);
	
	//pcapのオープン
	pd = pcap_open_offline(argv[1], ebuf);
	if (pd == NULL) {
		fprintf(stderr, "pcap_open_offline : %s", ebuf);
		exit(1);
	}

	if (pcap_compile(pd, &fp, filter_exp, 0, net) == -1) {
		 fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(pd));
		 return(1);
	}
	if (pcap_setfilter(pd, &fp) == -1) {
		 fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(pd));
		 return(1);
	}

	/* パケットの取得　永久ループ */
	if (pcap_loop(pd, -1, packet_pro, NULL) < 0) {
		fprintf(stderr, "pcap_loop : %s\n", pcap_geterr(pd));
		exit(1);
	}

	pcap_close(pd);	

	while(top!=NULL)
		init_d_list(top);
	
	return 0;
}

void udp_head(u_char *packet, struct ip *iph){
	packet = &packet[8];//DNS header is 8 byte
	sprintf(proto, "udp");
	q_section(packet);
}

void tcp_head(u_char *packet, struct ip *iph){
	struct tcphdr *tcph = (struct tcphdr *)packet;//tcpheader
	sprintf(proto, "tcp");

	if((int)tcph->th_flags != 24)//flag ACK PSH only
		return;
	
	packet = &packet[tcph->th_off*4];//payload point
	
	int size_pay = iph->ip_len/256 - iph->ip_hl*4 - tcph->th_off*4;//data size of payload
	if (size_pay <= 12){ //DNS header==12
		char sip_proto[20];
		sprintf(sip_proto, "%s:tcp", sip);
		insert_d_list(packet, size_pay, sip_proto);
		return;
	}
	
	if(size_pay != ((int)packet[0]*256 + (int)packet[1] + 2)){//I dont know reason of 2
		char sip_proto[20];
		sprintf(sip_proto, "%s:tcp", sip);
		d_list *p = insert_d_list(packet, size_pay, sip_proto);
		if (p->p_size == ((int)p->packet[0]*256 + (int)p->packet[1] + 2)){
			sprintf(p->sip, "0");
			q_section(&p->packet[2]);
		}
		return;
	}

	q_section(&packet[2]);

	return;
}

void q_section(u_char *packet){
	packet = &packet[2];
	d_list *p;
	if((int)packet[0] >= 128){//response
		if((p=find_d_list("0"))!=NULL)
			init_d_list(p);
		return;
	}
	packet = &packet[2];
	int q_count = (int)packet[0] * 256 + (int)packet[1];//question_count
	packet = &packet[8];
	int i;
	for(i=0; i<q_count; i++){
		int len_label=(int)packet[0];//label length
		if(len_label==0){//Malformed
			snprintf(domain, MAX_SIZE, "Malformed Packet.");
			q_count=1;
		}
		int j=0;
		char *tmp;

		while(len_label != 0){
			packet = &packet[1];
			
			for(j=0; j<len_label; j++){
				if(packet[j]==0){
					//strncat cant be used. I dont know reason.
					//tmp = strdup(domain);
					snprintf(domain, MAX_SIZE, "Malformed Packet");
					//free(tmp);
					q_count=1;
					j=len_label;
					packet[len_label] = 0;
				}
				else if((int)packet[j] > 32 && (int)packet[j] < 128){//alphabet code
					tmp = strdup(domain);
					snprintf(domain, MAX_SIZE, "%s%c", tmp, packet[j]);
					free(tmp);
				}
				else{
					tmp = strdup(domain);
					snprintf(domain, MAX_SIZE, "%s\\0x%02X", tmp, packet[j]);
					free(tmp);
				}
			}

			strncat(domain, ".", MAX_SIZE-strlen(domain)-1);
			packet = &packet[len_label];//next label
			len_label = (int)packet[0];//next label length
		}

		packet = &packet[1];
		
		printf("%s||%s||%s||%s||%s||", date, sip, dip, proto, domain);
		if(strcmp(domain, "Malformed Packet."))
			printf("%d",(int)packet[0]*256+(int)packet[1]);
		else
			printf("-1");

		//printf("||No answer||0\n");
		printf("\n");
		snprintf(domain, 2, "\0");
	}

	if((p=find_d_list("0"))!=NULL)
		init_d_list(p);


	return;
}

d_list *set_d_list(u_char *plus_pac, u_int p_size, char *sip, d_list *p){
	//set d_list to *p
	int i, count=0;
	for(i=0; i<p_size; i++){
		if(i + (int)p->p_size < MAX_SIZE){
			strncpy(&p->packet[i+(int)p->p_size], &plus_pac[i], 1);
			count++;
		}
	}
	sprintf(p->sip, "%s", sip);
	p->p_size+=count;
	return p;
}

d_list *insert_d_list(u_char *plus_pac, u_int p_size, char *sip){
	//if already there is same sip in d_list, set values to it
	//if there is not same sip, make d_list and set value
	d_list *p = find_d_list(sip);
	if(top == NULL){
		p = (d_list *)malloc(sizeof(d_list));
		p->packet = (u_char *)malloc(sizeof(u_char)*MAX_SIZE);
		p->p_size = 0;
		top = p;
		p->next=NULL;
	}else if(p == NULL){
		p = (d_list *)malloc(sizeof(d_list));
		p->packet = (u_char *)malloc(sizeof(u_char)*MAX_SIZE);
		p->p_size = 0;
		d_list *tmp;
		for(tmp=top; tmp->next!=NULL; tmp=tmp->next){}
		tmp->next = p;
		p->next=NULL;
	}

	set_d_list(plus_pac, p_size, sip, p);

	return p;
}

d_list *find_d_list(char *sip){
	//find d_list which have same sip
	d_list *p = top;
	while(1){
		if(p == NULL)
			return NULL;
		else if(!strcmp(sip, p->sip))
			return p;
		else
			p=p->next;
	}
}

void init_d_list(d_list *p){//p is not NULL
	d_list *tmp;
	if(top==p){
		tmp = top->next;
		free(top);
		top = tmp;
	}
	else{
		for(tmp=top; tmp->next!=p; tmp=tmp->next){}
		tmp->next = p->next;
		free(p);
	}
	return;
}

u_char *frag_ip_check(u_char *packet, struct ip *iph){
	char sip_proto[20];
	sprintf(sip_proto, "%s:ip", sip);
	int ip_tot_len = (int)((iph->ip_len&255)<<8)+(int)((iph->ip_len)>>8); 
	if ((int)(iph->ip_off&32) == 32){//fragment ip
		insert_d_list(packet, ip_tot_len-iph->ip_hl*4, sip_proto);
		return NULL;
	}else{
		d_list *p = find_d_list(sip_proto);
		if (p != NULL){
			insert_d_list(packet, ip_tot_len-iph->ip_hl*4, sip_proto);
			sprintf(p->sip, "0");
			return p->packet;
		}else{
			return packet;
		}
	}
}

void packet_pro(u_char *usr, const struct pcap_pkthdr *header, const u_char *packet){
	struct ip *iph; //IP header
	u_int size_ether = sizeof(struct ether_header); //eather header size
	u_int size_ip; //IP header size
	u_int size_vlan = 0; //vlan header size
	
	u_char *c_packet; //current pointer of packet

	iph = (struct ip *)(packet + size_ether + size_vlan);
	size_ip = iph->ip_hl * 4;
	c_packet = (u_char *)(packet + size_ether + size_vlan + size_ip);

	//年月日時分秒
	struct tm *tmdate = localtime(&header->ts.tv_sec);
	sprintf(date, "%4d-%02d-%02d %02d:%02d:%02d.%06d", 1900 + tmdate->tm_year, tmdate->tm_mon + 1, tmdate->tm_mday, tmdate->tm_hour, tmdate->tm_min, tmdate->tm_sec, header->ts.tv_usec);
	//sip,dip
	sprintf(sip, "%u.%u.%u.%ld", iph->ip_src.s_addr & 255, (iph->ip_src.s_addr & 65280) / 256, (iph->ip_src.s_addr & 16711680) / 65281, (iph->ip_src.s_addr & 4278190080) / 16711681);
	sprintf(dip, "%u.%u.%u.%ld", iph->ip_dst.s_addr & 255, (iph->ip_dst.s_addr & 65280) / 256, (iph->ip_dst.s_addr & 16711680) / 65281, (iph->ip_dst.s_addr & 4278190080) / 16711681);

	if((c_packet = frag_ip_check(c_packet, iph)) == NULL)
		return;
	
	switch((unsigned int)iph->ip_p){
	case 6://tcp
		tcp_head(c_packet, iph);
		break;
	case 17://udp
		udp_head(c_packet, iph);
		break;
	}
	fflush(stdout);

	return;
}

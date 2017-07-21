#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "time.h"

#include "pcap.h" //pcapライブラリ

#include <netinet/in.h>
#include <netinet/if_ether.h> //ethernetヘッダの定義
#include <netinet/ip.h> //ipヘッダの定義
#ifndef __FAVOR_BSD
# define __FAVOR_BSD
#endif
#include <netinet/tcp.h> //tcpヘッダの定義
#include <netinet/udp.h> //udpヘッダの定義

#define MAX_SIZE 1000

void packet_pro(u_char *Record_type, struct pcap_pkthdr *header, const u_char *packet);
void udphead(u_char *dnspac);
void tcphead(u_char *dnspac, struct ip *iph);
void q_section(u_char *dnspac);
typedef struct
{
	u_char pl[MAX_SIZE];
	u_int size;
	int init;
	char ip[16];
} div_mem;
div_mem dm;
void set_div_mem(u_char *ppl, u_int psize, char *ip) {
	int i;
	for (i = 0; i < psize; i++) {
		strncpy(&dm.pl[i + (int)dm.size], &ppl[i], 1);
	}
	sprintf(dm.ip, "%s", ip);
	dm.size += psize;
	dm.init++;
	//printf("pl=%02X%02X,size=%d,ip=%s\n",dm.pl[0],dm.pl[1],dm.size,dm.ip);
}
void init_div_mem() {
	dm.size = 0;
	dm.init = 0;
	sprintf(dm.pl, "\0\0");
}

pcap_t *pd; //pcapディスクリプタ
char date[27] = "0000-00-00 00:00:00.000000";
char sip[16] = "000.000.000.000";
char dip[16] = "000.000.000.000";
char proto[4];
char query[MAX_SIZE];
//char type[10];
//char answer[MAX_SIZE];

int main(int argc, char const *argv[])
{

	char cmd[200];//gzip解凍
	char filename[40];
	char ebuf[PCAP_ERRBUF_SIZE]; //pcap初期化時のエラーメッセ―ジ格納
	init_div_mem();

	//dump-XXXXXXXXXXXX
	if (argc != 2) {
		printf("usage:reqpassivedns <unixtime>\n");
		return 0;
	}

	sprintf(cmd, "gzip -cd /root/dumpfile/dump-%s.gz | tcpdump -r - -w /root/dumpfile/query-%s.pcap vlan and dst port domain and dst host '130.158.68.25'", argv[1], argv[1]);
	//printf("%s\n",cmd);
	system(cmd);
	sprintf(filename, "/root/dumpfile/query-%s.pcap", argv[1]);


	//pcapのオープン
	pd = pcap_open_offline(filename, ebuf);
	if (pd == NULL) {
		fprintf(stderr, "pcap_open_offline : %s", ebuf);
		exit(1);
	}

	/* パケットの取得　永久ループ */
	if (pcap_loop(pd, -1, packet_pro, NULL) < 0) {
		fprintf(stderr, "pcap_loop : %s\n", pcap_geterr(pd));
		exit(1);
	}

	pcap_close(pd);

	remove(filename);

	return 0;
}

void udphead(u_char *dnspac) {
	dnspac = &dnspac[8];
	sprintf(&proto, "udp");
	q_section(dnspac);
}

void tcphead(u_char *dnspac, struct ip *iph) {
	struct tcphdr *tcph = dnspac;//tcp header
	sprintf(&proto, "tcp");
	if ((int)tcph->th_flags != 24)return;

	int size_pl = iph->ip_len / 256 - iph->ip_hl * 4 - tcph->th_off * 4;
	if (size_pl <= 12) { //DNSheader==12
		set_div_mem(&dnspac[tcph->th_off * 4], size_pl, sip);
		return;
	}
	dnspac = &dnspac[(tcph->th_off * 4)];//なぜ2か不明length
	if (size_pl != ((int)dnspac[0] * 256 + (int)dnspac[1] + 2) && !strcmp(dm.ip, sip)) {
		set_div_mem(dnspac, size_pl, sip);
		if (dm.size == (int)dm.pl[0] * 256 + (int)dm.pl[1] + 2) {
			dm.init = -99;
			q_section(&dm.pl[2]);
		}
		return;
	}
	dnspac = &dnspac[2];
	q_section(dnspac);
}

void q_section(u_char *dnspac) {
	dnspac = &dnspac[2];
	if ((int)dnspac[0] >= 128)return; //レスポンスなので終了
	dnspac = &dnspac[2];
	int qcount = (int)dnspac[0] * 256 + (int)dnspac[1];//question count
	dnspac = &dnspac[8];

	int i = 0;
	for (i = 0; i < qcount; i++) {
		printf("%s||%s||%s||%s||", date, sip, dip, proto);

		int label_l = 0, i = 0;
		label_l = (int)dnspac[0];//ラベルの長さ
		while (label_l != 0)
		{
			dnspac = &dnspac[1]; //ラベルの先頭へ
			for (i = 0; i < label_l; i++)
			{
				if(dnspac[i]==NULL){
					printf("Malformed Packet");
					label_l=0;
				}
				else if ((int)dnspac[i] > 32 && (int)dnspac[i] < 128)
					printf("%c", dnspac[i]);
				else
					printf("\\0x%02X", dnspac[i]);
			}
			printf(".");
			dnspac = &dnspac[label_l]; //次のラベルの長さ部分へ
			label_l = (int)dnspac[0];//ラベルの長さ
		}
		dnspac = &dnspac[1];

		printf("||");
		//printf("%d",(int)dnspac[0]*256+(int)dnspac[1]);
		switch ((int)dnspac[0] * 256 + (int)dnspac[1]) {
		case 1: printf("A"); break;
		case 2: printf("NS"); break;
		case 5: printf("CNAME"); break;
		case 6: printf("SOA"); break;
		case 12: printf("PTR"); break;
		case 15: printf("MX"); break;
		case 16: printf("TXT"); break;
		case 17: printf("RP"); break;
		case 28: printf("AAAA"); break;
		case 29: printf("LOC"); break;
		case 33: printf("SRV"); break;
		case 44: printf("SSHFP"); break;
		case 255: printf("ANY"); break;
		default: printf("unknown");break;
		}

		printf("||No answer||0\n");

		if (dm.init == -99)
			init_div_mem();
	}

}

void packet_pro(u_char *usr, struct pcap_pkthdr *header, const u_char *packet) {

	struct ip *iph ;//IPヘッダ
	u_int size_ether = sizeof(struct ether_header); //etherヘッダの大きさ
	u_int size_ip; //IPヘッダの大きさ

	int i, j, type, con;
	u_char *pac;//現在のポインタ

	iph = (struct ip *)(packet + size_ether + 4);
	size_ip = 4 * iph->ip_hl;
	pac = (u_char *)(packet + size_ether + size_ip + 4);

	//年月日時分秒
	struct tm *tmdate = localtime(&header->ts.tv_sec);
	sprintf(&date, "%4d-%02d-%02d %02d:%02d:%02d.%06d", 1900 + tmdate->tm_year, tmdate->tm_mon + 1, tmdate->tm_mday, tmdate->tm_hour, tmdate->tm_min, tmdate->tm_sec, header->ts.tv_usec);
	//sip,dip
	sprintf(&sip, "%u.%u.%u.%ld", iph->ip_src.s_addr & 255, (iph->ip_src.s_addr & 65280) / 256, (iph->ip_src.s_addr & 16711680) / 65281, (iph->ip_src.s_addr & 4278190080) / 16711681);
	sprintf(&dip, "%u.%u.%u.%ld", iph->ip_dst.s_addr & 255, (iph->ip_dst.s_addr & 65280) / 256, (iph->ip_dst.s_addr & 16711680) / 65281, (iph->ip_dst.s_addr & 4278190080) / 16711681);

	switch ((unsigned int)iph->ip_p) {
	case 6://tcp
		tcphead(pac, iph);
		break;
	case 17://udp
		udphead(pac);
		break;
	}

	fflush(stdout);
}

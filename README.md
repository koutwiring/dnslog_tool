# dnslog_tool
* What is:  
This tool is to make DNS query log data from pcap file.  
No use response packet.
This use libpcap, so you need install libpcap.
Log data maked this tool can used some analysis of DNS.  
This is not completed.  

* usage:  
`$ gcc -o dns_query_log dns_query_log.c -lpcap`  
`$ ./dns_query_log <pcap_file> <DNS server IP which you use> > output.log`  
  
* How to save pcap file:  
`$ tcpdump -n -w output.pcap`  
 
* Data attribute:  
Date || Source IP || Destination IP (DNS server) || Protocol || Domain Name || Record Type ID  
Record Type ID details (https://en.wikipedia.org/wiki/List_of_DNS_record_types)  

__You can use this tool freely, but I cannot take responsibility for it.__  
Thank you.  

* dns_query_log.cとは  
このツールはpcapファイルからDNSクエリーのログデータを作成するものです。  
応答パケットではありません。  
libpcapを用いて作成しているため、使う場合はlibpcapをインストールしてからご使用ください。  
ログデータはDNSの分析に使えるでしょう。  

* 使い方  
`$ gcc -o dns_query_log dns_query_log.c -lpcap`  
`$ ./dns_query_log <pcapファイル> <ご使用中のDNSサーバのIPアドレス> > output.log`  

* pcapファイルの保存方法  
`$ tcpdump -n -w output.pcap`  

* データの属性  
日時時間 || 送信元IP || 送信先IP（DNSサーバ） || プロトコル || ドメイン名 || レコードタイプID  
レコードタイプIDに関してはwikipediaを参照ください（https://ja.wikipedia.org/wiki/DNS%E3%83%AC%E3%82%B3%E3%83%BC%E3%83%89%E3%82%BF%E3%82%A4%E3%83%97%E3%81%AE%E4%B8%80%E8%A6%A7）  

基本的なパケットに対しては正しく動作しますが一部特殊なパケット（不正な形式のもの）などで正しく動作しない可能性はあります。(正しく動くようにしているつもりではありますが)  
__自由に使用して構いませんが、一切の責任は持ちかねます。__  

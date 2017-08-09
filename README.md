# dnslog_tool
* What is:  
This tool is to make DNS query log data from pcap file.  
No use response packet.  
Log data maked this tool can used some analysis of DNS.  

* usage:  
`$ gcc -o dns_query_log.c dns_query_log -lpcap`  
`$ ./dns_query_log <pcap_file> <DNS server IP which you use> > output.log`  
  
* How to save pcap file:  
`$ tcpdump -n -w output.pcap`  
 
* Data attribute:  
Date || Source IP || Destination IP (DNS server) || Protocol || Domain Name || Record Type ID  
Record Type ID details (https://en.wikipedia.org/wiki/List_of_DNS_record_types)  


__You can use this tool freely, but I cannot take responsibility for it.__  
Thank you.  

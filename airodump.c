#include <stdio.h>
#include <pcap.h>

void test(const unsigned char*);

int airodump(const char* interface) {

    char errbuf[PCAP_ERRBUF_SIZE];
    const char* ifname = interface;

    // pcap open live
    pcap_t* handle = pcap_open_live(ifname, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s(%s)\n", ifname, errbuf);
		return -1;
	}

    struct pcap_pkthdr* header;
	const unsigned char* packet; // const u_char* packet;

    while(1) {

        // pcap next ex
        int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

        test(packet);
        
    }


    pcap_close(handle);
    return 0;

}


// 캡처된 패킷을 확인하는 코드
void test(const unsigned char* pkt) {
    printf("captured bytes: ");
    for(int i=0; i<40; i++)
        printf("%02x ", *(pkt + i));
    putchar('\n');
}

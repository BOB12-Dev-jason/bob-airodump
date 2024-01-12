#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>

#include "radiotap.h"

void test(const unsigned char* pkt);
void parse_present(uint32_t present);

typedef struct ieee80211_radiotap_header radiotapHeader;

int airodump(const char* interface) {

    char errbuf[PCAP_ERRBUF_SIZE];
    const char* ifname = interface;

    // pcap open live
    // pcap_t* handle = pcap_open_live(ifname, BUFSIZ, 1, 1000, errbuf);
    pcap_t* handle = pcap_open_offline(ifname, errbuf);
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

        radiotapHeader* radio_header;
        radio_header = packet;
        puts("packet captured");
        printf("radiotap-header version: %02x\n", radio_header->it_version);
        printf("radiotap-header pad: %02x\n", radio_header->it_pad);
        printf("radiotap-header length: %02x(dec %d)\n", radio_header->it_len, radio_header->it_len);
        printf("radiotap-header present: %02x\n\n", radio_header->it_present);

        uint32_t present = radio_header->it_present;
        parse_present(present);
        
        // test(packet);
        
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


void parse_present(uint32_t present) {
    uint8_t val;
    for(int i=32; i>=0; i--) {
        val = (present >> i) & 1; // 각 비트값이 1인지 확인
        if(val == 1) {
            printf("bit %d: %02x\n", i, val);
            // i는 present의 비트 자릿값. 자릿수마다 정의된 enum과 비교.
            switch (i)
            {
            case IEEE80211_RADIOTAP_TSFT:
                /* code */
                break;
            
            case IEEE80211_RADIOTAP_FLAGS:
                break;
            
            case IEEE80211_RADIOTAP_RATE:
                break;
            
            case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
                break;
            
            case IEEE80211_RADIOTAP_EXT:
                break;
            
            default:
                break;
            }
        }
            
    }
}

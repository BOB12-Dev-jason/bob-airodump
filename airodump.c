#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>

#include "radiotap.h"
#include "mac.h"

void test(const unsigned char* pkt);
void parse_present(uint32_t* present);
void printMac(uint8_t addr[]);

typedef struct ieee80211_radiotap_header radiotapHeader;
typedef struct ieee80211_MacHeader macHeader;

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

        // 편법 쓰면 그냥 (radio length - 1) 위치에 antenna signal 있을 것 같기도 함
        uint32_t present = radio_header->it_present;
        if((present >> 5) & 1) {
            // antenna signal 있을 때만 파싱
            puts("dbm antenna signal bit is 1");
            parse_present(&present);
        }
        
        macHeader* machdr = (packet + radio_header->it_len);
        puts("print macHeader");
        printf("macheader-frameControl: %02x\n", ntohl(machdr->frame_control));
        printf("macheader-duration: %02x\n", machdr->duration);
        printf("macheader-addr1:");
        printMac(machdr->addr1);
        printf("macheader-addr2:");
        printMac(machdr->addr2);
        printf("macheader-addr3:");
        printMac(machdr->addr3);
        printf("macheader-seq_control: %02x\n\n", machdr->seq_control);

        uint16_t tmp = (machdr->frame_control >> 8);
        // if((frame_ctl & 0x00))


        
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

void printMac(uint8_t addr[]) {
    for(int i=0; i<6; i++)
        printf("%02x ", addr[i]);
    putchar('\n');
}


void parse_present(uint32_t* present) {
    unsigned int dbm_antsignal_offset = 0; // present flags로부터 신호 세기까지의 offset
    int ext_flag = 0;
    uint8_t val;
    for(int i=32; i>=0; i--) {
        val = (*present >> i) & 1; // 각 비트값이 1인지 확인
        if(val == 1) {
            printf("bit %d: %02x\n", i, val);
            // i는 present의 비트 자릿값. 자릿수마다 정의된 enum과 비교.
            switch (i)
            {
            case IEEE80211_RADIOTAP_TSFT:
                dbm_antsignal_offset += 8; // MAC Timestamp가 추가되어 8byte 추가
                break;
            
            case IEEE80211_RADIOTAP_FLAGS:
                dbm_antsignal_offset += 1; // signals 1byte 추가
                break;
            
            case IEEE80211_RADIOTAP_RATE:
                dbm_antsignal_offset += 1; // Rate 1byte 추가
                break;
            
            case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
                break;
            
            case IEEE80211_RADIOTAP_EXT:
                dbm_antsignal_offset += 4; // present flag 4byte 추가
                ext_flag = 1;
                // parse_present(present + 4); // 4바이트 뒤를 다시 파싱
                break;
            
            default:
                break;
            }
        }
            
    } // for
    if(ext_flag) {
        puts("next present flag is present");
        parse_present(present + 4);
    }
}

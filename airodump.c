#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <string.h>

#include "radiotap.h"
#include "macHeader.h"

typedef struct ieee80211_radiotap_header radiotapHeader;
typedef struct ieee80211_MacHeader macHeader;

void test(const unsigned char* pkt);
void parse_present(uint32_t* present);
void printMac(uint8_t addr[]);
int is_beaconFrame(macHeader* hdr);

typedef struct {
    unsigned char bssid[20];
    int pwr;
    int beacons;
    int channel;
    unsigned char ESSID[256];
} frameInfo;


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
    
    frameInfo infos[512];
    int bssid_count = 0;
    int is_new_bssid;

    while(1) {

        is_new_bssid = 1;
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
        printf("macheader-frameControl: %02x\n", ntohs(machdr->frame_control));
        printf("macheader-duration: %02x\n", machdr->duration);
        printf("macheader-addr1:");
        printMac(machdr->addr1);
        printf("macheader-addr2:");
        printMac(machdr->addr2);
        printf("macheader-addr3:");
        printMac(machdr->addr3);
        printf("macheader-seq_control: %02x\n\n", machdr->seq_control);

        // 비콘 프레임인 경우 추가하거나 beacons 증가
        if(is_beaconFrame(machdr)) {
            uint8_t* bssid_arr = machdr->addr3;
            char tmp_bssid[20];
            sprintf(tmp_bssid,
                    "%02x:%02x:%02x:%02x:%02x:%02x",
                    bssid_arr[0], bssid_arr[1], bssid_arr[2], bssid_arr[3], bssid_arr[4], bssid_arr[5]);
            
            printf("tmp bssid: %s\n", tmp_bssid);

            // 새로운 bssid인지 확인
            for(int i=0; i<512; i++) {
                const char* beacon_bssid = infos[i].bssid;
                if(strcmp(beacon_bssid, tmp_bssid) == 0) {
                    infos[i].beacons++;
                    is_new_bssid = 0;
                    break;
                }
            }

            if(is_new_bssid) {
                // infos[bssid_count++].bssid = tmp_bssid;

            }

            // 새로운 bssid가 맞으면 infos에 추가

            // 아니면 기존 bssid의 비콘 프레임 카운트 증가
            puts("it is beacon Frame");
            printf("BSSID: ");
            printMac(machdr->addr3);
        }


        

        
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


void printInfo() {
    puts("BSSID\tPWR\tBeacons\tChannel\tESSID");
}


int is_beaconFrame(macHeader* hdr) {
    uint16_t BE_frame_ctl = ntohs(hdr->frame_control); // 빅엔디안 frame control field
    uint8_t subtype = BE_frame_ctl >> 12;
    uint8_t type = (BE_frame_ctl >> 10) & 0b11;
    uint8_t ver = (BE_frame_ctl >> 8) & 0b11;
    // type이 00이면 관리프레임, subtype이 1000이면 비콘 프레임
    if((type==0b00) && (subtype==0b1000)) return 1;
    else return 0;
    // printf("subtype: %x\n", subtype);
    // printf("type: %x\n", type);
    // printf("ver: %x\n", ver);
}


void printMac(uint8_t addr[]) {
    for(int i=0; i<5; i++)
        printf("%02x:", addr[i]);
    printf("%02x", addr[5]);
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

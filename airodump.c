#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>

#include "radiotap.h"
#include "macHeader.h"
#include "beaconFrameBody.h"

typedef struct ieee80211_radiotap_header radiotapHeader;
typedef struct ieee80211_MacHeader macHeader;
typedef struct ieee80211_beaconFrameBody beaconBody;

int parse_present(uint32_t* present);
int8_t get_antsignal_offset(radiotapHeader* hdr);
void printMac(uint8_t addr[]);
int is_beaconFrame(macHeader* hdr);

typedef struct {
    uint8_t flags;
    uint8_t rate;
    uint16_t frequency;
    uint16_t channel_flags;
    uint8_t antenna_signal;
} radio_more_hdr;

typedef struct {
    uint8_t tagNum;
    uint8_t tagLen;
} tagParam;

typedef struct {
    unsigned char bssid[20];
    int8_t pwr;
    int beacons;
    int channel;
    unsigned char essid[256];
} frameInfo;


int airodump(const char* interface) {

    char errbuf[PCAP_ERRBUF_SIZE];
    const char* ifname = interface;

    // pcap open live
    pcap_t* handle = pcap_open_live(ifname, BUFSIZ, 1, 1000, errbuf);
    // pcap_t* handle = pcap_open_offline(ifname, errbuf);
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

        radio_more_hdr* more_hdr = ((uint8_t*)radio_header + 8);
        // radiotap header에서 고정길이 8byte + present에 ext 있으면 4byte 추가 + radio_more_hdr에 넣기
        if (radio_header->it_present & (1 << IEEE80211_RADIOTAP_DBM_ANTSIGNAL)) {
            if (radio_header->it_present & (1 << IEEE80211_RADIOTAP_CHANNEL)) {
                puts("Antenna Signal flag active");
                more_hdr = (uint8_t*)more_hdr + 4;
            }
        }

        uint8_t dbm_antsig_pwr = more_hdr->antenna_signal;
        printf("Antenna Signal Strength: %ddBm\n", more_hdr->antenna_signal);

        // int captured_channel = get_channel_num(frequency);
        // printf("captued_channel: %d\n", captured_channel);
        // printf("radiotap-header version: %02x\n", radio_header->it_version);
        // printf("radiotap-header pad: %02x\n", radio_header->it_pad);
        // printf("radiotap-header length: %02x(dec %d)\n", radio_header->it_len, radio_header->it_len);
        // printf("radiotap-header present: %02x\n\n", radio_header->it_present);

        // 편법 쓰면 그냥 (radio length - 1) 위치에 antenna signal 있을 것 같기도 함
        uint32_t present = radio_header->it_present;
        if((present >> 5) & 1) {
            // antenna signal 있을 때만 파싱
            // puts("dbm antenna signal bit is 1");
            // parse_present(&present);
        }
        
        macHeader* machdr = (packet + radio_header->it_len);
        // puts("print macHeader");
        // printf("macheader-frameControl: %02x\n", ntohs(machdr->frame_control));
        // printf("macheader-duration: %02x\n", machdr->duration);
        // printf("macheader-addr1:");
        // printMac(machdr->addr1);
        // printf("macheader-addr2:");
        // printMac(machdr->addr2);
        // printf("macheader-addr3:");
        // printMac(machdr->addr3);
        // printf("macheader-seq_control: %02x\n\n", machdr->seq_control);

        // 비콘 프레임인 경우에 대한 처리
        if(is_beaconFrame(machdr)) {
            uint8_t* bssid_arr = machdr->addr3;
            char tmp_bssid[20];
            sprintf(tmp_bssid,
                    "%02x:%02x:%02x:%02x:%02x:%02x",
                    bssid_arr[0], bssid_arr[1], bssid_arr[2], bssid_arr[3], bssid_arr[4], bssid_arr[5]);
            
            // printf("tmp bssid: %s\n", tmp_bssid);


            beaconBody* body = ((uint8_t*)machdr + 24); // mac header의 24byte 뒤부터 프레임 몸체 (beacon frame의 길이는 24byte)
            // printf("beacon body timestamp: %02x\n", body->timestamp);
            // printf("beacon body beacon_interval: %02x\n", body->beacon_interval);
            // printf("beacon body cap_info: %02x\n", body->cap_info);
            // printf("beacon body tag length: %02x\n", body->tag_length);

            // 새로운 bssid인지 확인
            for(int i=0; i<512; i++) {
                const char* beacon_bssid = infos[i].bssid;
                // 기존에 있던 bssid인 경우 beacons 1 증가
                if(strcmp(beacon_bssid, tmp_bssid) == 0) {
                    infos[i].beacons++;
                    infos[i].pwr = dbm_antsig_pwr;
                    // if(captured_channel != -1)
                    //     infos[i].channel = captured_channel;
                    is_new_bssid = 0;
                    break;
                }
            }

            // 새로운 bssid가 맞으면 infos에 추가
            if(is_new_bssid) {
                frameInfo* info = &(infos[bssid_count]);
                strcpy(info->bssid, tmp_bssid);
                // strcpy(infos[bssid_count].bssid,tmp_bssid);
                info->beacons = 1;

                // ssid (essid) 추출
                uint8_t* ssid_addr = ((uint8_t*)body + 14);
                int ssid_length = body->tag_length;
                unsigned char* tmp_essid = calloc(1, ssid_length + 1);
                strncpy(tmp_essid, ssid_addr, ssid_length);
                tmp_essid[ssid_length] = '\0';
                strcpy(info->essid, tmp_essid);

                // channel 추출
                uint8_t* tag_param_addr = ((uint8_t*)body + 12);
                tagParam *p = tag_param_addr;
                uint8_t tag_num = p->tagNum;
                while(p->tagNum != 3) {
                    uint8_t tag_length = p->tagLen;
                    p = (uint8_t*)p + (2 + tag_length); // tagNum(1byte) + taglen(1byte) + length(가변)
                }
                uint8_t tmp_channel = *((uint8_t*)p + 2);
                printf("tmp_channel: %d\n", tmp_channel);
                info->channel= tmp_channel;

                info->pwr = dbm_antsig_pwr;

                bssid_count++;
            }

        }

        puts("BSSID\t\t\tPWR\tBeacons\t\tChannel\t\tESSID");
        for(int i=0; i<bssid_count; i++) {
            printf("%s\t%d\t%d\t\t%d\t\t%s\n", infos[i].bssid, infos[i].pwr, infos[i].beacons, infos[i].channel, infos[i].essid);
        }
        
    } // while(1)

    pcap_close(handle);
    return 0;

} // int airodump()

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


// deprecated
void printMac(uint8_t addr[]) {
    for(int i=0; i<5; i++)
        printf("%02x:", addr[i]);
    printf("%02x", addr[5]);
    putchar('\n');
}


int8_t get_antsignal_offset(radiotapHeader* hdr) {
    int8_t offset = 0;
    if (hdr->it_present & (1 << IEEE80211_RADIOTAP_EXT)) {
        offset += 4;
    }
    if (hdr->it_present & (1 << IEEE80211_RADIOTAP_DBM_ANTSIGNAL)) {
        offset + 14;
        // printf("Antenna Signal Strength: %ddBm\n", dbm_antsignal);
    }
    return offset;
}


// deprecated
int parse_present(uint32_t* present) {
    int additional_length; // present flags로부터 신호 세기까지의 offset
    int ext_flag;
    uint8_t val;
    for(int i=32; i>=0; i--) {
        val = (*present >> i) & 1; // 각 비트값이 1인지 확인
        if(val == 1) {
            printf("bit %d: %02x\n", i, val);
            // i는 present의 비트 자릿값. 자릿수마다 정의된 enum과 비교.
            switch (i)
            {
            case IEEE80211_RADIOTAP_TSFT:
                additional_length += 8; // MAC Timestamp가 추가되어 8byte 추가
                break;
            
            case IEEE80211_RADIOTAP_FLAGS:
                additional_length += 1; // signals 1byte 추가
                break;
            
            case IEEE80211_RADIOTAP_RATE:
                additional_length += 1; // Rate 1byte 추가
                break;
            
            case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
                break;
            
            case IEEE80211_RADIOTAP_EXT:
                additional_length += 4; // present flag 4byte 추가
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

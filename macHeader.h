#ifndef BOB12_MACHEADER_H_HDXIAN
#define BOB12_MACHEADER_H_HDXIAN

#include <stdint.h>

// struct frameControl {
//     uint16_t proto_ver;
//     uint16_t type;
//     uint32_t subtype;
//     uint16_t ds; // 00: 단말간, 01: ap->단말, 10: 단말->ap, 11: ap간 무선 브리지
//     // uint8_t tods;
//     // uint8_t fromds;
//     uint8_t moreflag;
//     uint8_t retry;
//     uint8_t power_mgmt;
//     uint8_t more_data;
//     uint8_t protected_frame;
//     uint8_t order;
// };

struct ieee80211_MacHeader {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_control;
    // addr4, qos, ... 는 optional
};


#endif
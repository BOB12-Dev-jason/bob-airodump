#ifndef BOB12_BEACONFRAMEBODY_H_HDXIAN
#define BOB12_BEACONFRAMEBODY_H_HDXIAN

#include <stdint.h>

struct ieee80211_beaconFrameBody {
    uint64_t timestamp;         // timestamp. 8 bytes
    uint16_t beacon_interval;   // beacon interval. 2 byte
    uint16_t cap_info;          // capability information. 2 byte
    uint8_t tag_num;
    uint8_t tag_length;
};

#endif
#include <stdio.h>

#include "airodump.h"

void usage();

int main(int argc, char* argv[]) {

    if(argc != 2) {
        usage();
        return 1;
    }

    int res = 0;
    const char* itf = argv[1];
    res = airodump(itf);

    return 0;
}

void usage() {
    puts("syntax: airodump <interface>");
    puts("sample: airodump wlan0");
}

#include <stdio.h>

#include "airodump.h"

int main(int argc, char* argv[]) {

    if(argc != 2) {
        usage();
        return 1;
    }

    int res = 0;
    res = airodump();

    return 0;
}

void usage() {
    puts("syntax: airodump <interface>");
    puts("sample: airodump wlan0");
}

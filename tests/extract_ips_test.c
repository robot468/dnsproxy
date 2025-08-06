#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>

int extract_ips_from_response(char *packet, ssize_t len, uint32_t *ips, int max_ips) {
    if (len < 12) return 0;
    int qdcount = ntohs(*(uint16_t*)(packet + 4));
    int ancount = ntohs(*(uint16_t*)(packet + 6));
    int nscount = ntohs(*(uint16_t*)(packet + 8));
    int arcount = ntohs(*(uint16_t*)(packet + 10));
    int pos = 12;

    // skip question section
    for (int i = 0; i < qdcount; i++) {
        while (pos < len && packet[pos] != 0) pos += packet[pos] + 1;
        pos += 5;
    }

    int found = 0;
    for (int i = 0; i < ancount && found < max_ips; i++) {
        if (pos + 12 > len) break;
        uint16_t type = ntohs(*(uint16_t*)(packet + pos + 2));
        uint16_t rdlen = ntohs(*(uint16_t*)(packet + pos + 10));
        if (type == 1 && rdlen == 4 && pos + 12 + 4 <= len) {
            memcpy(&ips[found], packet + pos + 12, 4);
            found++;
        }
        pos += 12 + rdlen;
    }

    // skip authority section
    for (int i = 0; i < nscount; i++) {
        if (pos + 12 > len) break;
        uint16_t rdlen = ntohs(*(uint16_t*)(packet + pos + 10));
        pos += 12 + rdlen;
    }

    // process additional section
    for (int i = 0; i < arcount && found < max_ips; i++) {
        if (pos + 12 > len) break;
        uint16_t type = ntohs(*(uint16_t*)(packet + pos + 2));
        uint16_t rdlen = ntohs(*(uint16_t*)(packet + pos + 10));
        if (type == 1 && rdlen == 4 && pos + 12 + 4 <= len) {
            memcpy(&ips[found], packet + pos + 12, 4);
            found++;
        }
        pos += 12 + rdlen;
    }

    return found;
}

int main(void) {
    unsigned char packet[] = {
        0x00,0x00, 0x81,0x80, 0x00,0x01, 0x00,0x01, 0x00,0x00, 0x00,0x01,
        0x07,'e','x','a','m','p','l','e', 0x03,'c','o','m',0x00, 0x00,0x01, 0x00,0x01,
        0xC0,0x0C, 0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x3C,0x00,0x04, 0x5d,0xb8,0xd8,0x22,
        0xC0,0x0C, 0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x3C,0x00,0x04, 0x01,0x02,0x03,0x04
    };

    uint32_t ips[10];
    int n = extract_ips_from_response((char*)packet, sizeof(packet), ips, 10);
    assert(n == 2);
    assert(ntohl(ips[0]) == 0x5db8d822);
    assert(ntohl(ips[1]) == 0x01020304);
    printf("extract_ips_from_response test passed\n");
    return 0;
}

// Updated unit test for extract_ips_from_response
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>

static int skip_name(char *packet, ssize_t len, int pos) {
    while (pos < len) {
        unsigned char c = (unsigned char)packet[pos];
        if (c == 0) {
            return pos + 1;
        }
        if ((c & 0xC0) == 0xC0) {
            if (pos + 1 < len) {
                return pos + 2;
            }
            return len;
        }
        pos += c + 1;
    }
    return len;
}

int extract_ips_from_response(char *packet, ssize_t len, uint32_t *ips, int max_ips) {
    if (len < 12) return 0;
    int qdcount = ntohs(*(uint16_t*)(packet + 4));
    int ancount = ntohs(*(uint16_t*)(packet + 6));
    int nscount = ntohs(*(uint16_t*)(packet + 8));
    int arcount = ntohs(*(uint16_t*)(packet + 10));
    int pos = 12;

    for (int i = 0; i < qdcount; i++) {
        pos = skip_name(packet, len, pos);
        pos += 4;
    }

    int found = 0;
    for (int i = 0; i < ancount && found < max_ips; i++) {
        pos = skip_name(packet, len, pos);
        if (pos + 10 > len) break;
        uint16_t type = ntohs(*(uint16_t*)(packet + pos));
        uint16_t rdlen = ntohs(*(uint16_t*)(packet + pos + 8));
        if (type == 1 && rdlen == 4 && pos + 14 <= len) {
            memcpy(&ips[found], packet + pos + 10, 4);
            found++;
        }
        pos += 10 + rdlen;
    }

    for (int i = 0; i < nscount; i++) {
        pos = skip_name(packet, len, pos);
        if (pos + 10 > len) break;
        uint16_t rdlen = ntohs(*(uint16_t*)(packet + pos + 8));
        pos += 10 + rdlen;
    }

    for (int i = 0; i < arcount && found < max_ips; i++) {
        pos = skip_name(packet, len, pos);
        if (pos + 10 > len) break;
        uint16_t type = ntohs(*(uint16_t*)(packet + pos));
        uint16_t rdlen = ntohs(*(uint16_t*)(packet + pos + 8));
        if (type == 1 && rdlen == 4 && pos + 14 <= len) {
            memcpy(&ips[found], packet + pos + 10, 4);
            found++;
        }
        pos += 10 + rdlen;
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

    unsigned char speedtest_packet[] = {
        0x00,0x00, 0x81,0x80, 0x00,0x01, 0x00,0x01, 0x00,0x00, 0x00,0x00,
        0x09,'s','p','e','e','d','t','e','s','t', 0x03,'n','e','t',0x00, 0x00,0x01, 0x00,0x01,
        0x09,'s','p','e','e','d','t','e','s','t', 0x03,'n','e','t',0x00,
        0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x3C,0x00,0x04, 0x97,0x65,0x02,0xDB
    };

    uint32_t ips2[10];
    int n2 = extract_ips_from_response((char*)speedtest_packet, sizeof(speedtest_packet), ips2, 10);
    assert(n2 >= 1);
    assert(ntohl(ips2[0]) == 0x976502db);

    printf("extract_ips_from_response tests passed\n");
    return 0;
}


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>

void dumphex(char *pfx, uint8_t *buf, int len, int txt) {
    int i, j;
    for (i = 0; i < len; i+= 16) {
        if (pfx)
            printf(pfx);
        for (j = 0; j < 16 && (i+j) < len; j++)
            printf(" %02x", buf[i+j]);
        if (txt) {
            while (j++ < 16)
                printf("   ");
            printf("   ");
            for (j = 0; j < 16 && (i+j) < len; j++)
                printf("%c", isprint(buf[i+j]) ? buf[i+j] : '.');
            while (j++ < 16)
                printf(".");
        }
        printf("\n");
    }
}

void dumpatt(char *pfx, uint8_t *buf, int len, uint16_t *lhnd) {
    if (len < 1)
        return;
    if (pfx)
        printf(pfx);
    switch(buf[0]) {
    case 0x00:
        puts("Undefined ATT PDU");
        break;
    case 0x01:
        if (5 != len) {
            puts("Malformed ERR PDU");
        } else {
            uint16_t hnd = (uint16_t)buf[2] | ((uint16_t)buf[3] << 8);
            printf("ERR: %02x req=%02x hnd=%04x\n", buf[4], buf[1], hnd);
        }
        break;
    case 0x02:
    case 0x03:
        if (3 != len) {
            puts("Malformed MTU PDU");
        } else {
            uint16_t mtu = (uint16_t)buf[1] | ((uint16_t)buf[2] << 8);
            printf("MTU: mtu=%04x\n", mtu);
        }
        break;
    case 0x04:
        if (5 != len) {
            puts("Malformed FND PDU");
        } else {
            uint16_t beg = (uint16_t)buf[1] | ((uint16_t)buf[2] << 8);
            uint16_t end = (uint16_t)buf[3] | ((uint16_t)buf[4] << 8);
            printf("FIND: beg=%04x end=%04x\n", beg, end);
        }
        break;
    case 0x05:
        if (2 > len) {
            puts("Short FIND PDU");
        } else {
            int blk;
            printf("FIND: fmt=%02x", buf[1]);
            switch (buf[1]) {
            case 0x01:
                blk = 4;
                break;
            case 0x02:
                blk = 18;
                break;
            default:
                puts("Invalid format");
                return;
            }
            for (int i = 2; i < len; i+= blk) {
                uint16_t hnd = (uint16_t)buf[i] | ((uint16_t)buf[i+1] << 8);
                if (lhnd)
                    *lhnd = hnd;
                if (4 == blk) {
                    uint16_t uid = (uint16_t)buf[i+2] | ((uint16_t)buf[i+3] << 8);
                    printf(", hnd=%04x uuid=%04x", hnd, uid);
                } else {
                    printf(", hnd=%04x uuid=", hnd);
                    dumphex("", buf+i+2, 16, 0);
                }
            }
            if (4 == blk)
                printf("\n");
        }
        break;
    case 0x08:
        if (7 > len) {
            puts("Malformed RTYP PDU");
        } else {
            uint16_t beg = (uint16_t)buf[1] | ((uint16_t)buf[2] << 8);
            uint16_t end = (uint16_t)buf[3] | ((uint16_t)buf[4] << 8);
            printf("RTYP: beg=%04x, end=%04x, typ=", beg, end);
            dumphex("", buf+5, len-5, 0);
        }
        break;
    case 0x09:
        if (2 > len) {
            puts("Malformed RTYP PDU");
        } else {
            printf("RTYP: blk=%02x\n", buf[1]);
            if (2 > buf[1]) {
                puts("Short blk (<2)");
            } else {
                for (int i=2; i<len; i+= buf[1]) {
                    uint16_t hnd = (uint16_t)buf[i] | ((uint16_t)buf[i+1] << 8);
                    if (lhnd)
                        *lhnd = hnd;
                    printf("\tRTYP: hnd=%04x\n", hnd);
                    dumphex("\tRTYP: ", buf+i+2, buf[1]-2, 0);
                }
            }
        }
        break;
    case 0x0A:
        if (3 != len) {
            puts("Malformed READ PDU");
        } else {
            uint16_t hnd = (uint16_t)buf[1] | ((uint16_t)buf[2] << 8);
            printf("READ: hnd=%04x\n", hnd);
        }
        break;
    case 0x0B:
        if (1 > len) {
            puts("Malformed READ PDU");
        } else {
            dumphex("READ: ", buf+1, len-1, 1);
        }
        break;
    case 0x10:
        if (7 > len) {
            puts("Malformed RGRP PDU");
        } else {
            uint16_t beg = (uint16_t)buf[1] | ((uint16_t)buf[2] << 8);
            uint16_t end = (uint16_t)buf[3] | ((uint16_t)buf[4] << 8);
            printf("RGRP: beg=%04x, end=%04x, grp=", beg, end);
            dumphex("", buf+5, len-5, 0);
        }
        break;
    case 0x11:
        if (2 > len) {
            puts("Malformed RGRP PDU");
        } else {
            printf("RGRP: blk=%02x\n", buf[1]);
            if (4 > buf[1]) {
                puts("Short blk (<4)");
            } else {
                for (int i=2; i<len; i+= buf[1]) {
                    uint16_t hnd = (uint16_t)buf[i] | ((uint16_t)buf[i+1] << 8);
                    uint16_t end = (uint16_t)buf[i+2] | ((uint16_t)buf[i+3] << 8);
                    if (lhnd)
                        *lhnd = hnd;
                    printf("\tRGRP: hnd=%04x end=%04x\n", hnd, end);
                    dumphex("\tRGRP: ", buf+4, buf[1]-4, 0);
                }
            }
        }
        break;
    case 0x12:
    case 0x52:
        if (3 > len) {
            puts("Malformed WRTE PDU");
        } else {
            uint16_t hnd = (uint16_t)buf[1] | ((uint16_t)buf[2] << 8);
            printf("WRTE: hnd=%04x: val=");
            dumphex("WRTE: ", buf+3, len-3, 1);
        }
        break;
    case 0x13:
        puts("WROK");
        break;
    default:
        printf("Unsupported PDU Opcode: %02x\n", buf[0]);
        break;
    }
    if (getenv("ATT_RAW") != NULL)
        dumphex("--RAW: ", buf, len, 1);
}

int transaction(int sock, uint8_t *out, int olen, uint8_t *in, int ilen, uint16_t *lhnd) {
    if (write(sock, out, olen) != olen) {
        perror("writing to socket");
        return -1;
    }
    dumpatt("SND> ", out, olen, NULL);
    ilen = read(sock, in, ilen);
    if (ilen < 0)
        perror("reading from socket");
    else
        dumpatt("RCV< ", in, ilen, lhnd);
    return ilen;
}

volatile int sigdone = 0;
void stop(int sig) {
    sigdone = 1;
}

int main(int argc, char **argv) {
    struct sockaddr_l2 l2addr = { 0 };
    char name[20];
    uint8_t out[512], in[512];
    int sock, nread;
    if (argc < 2) {
        puts("usage: blefun <bd address>");
        return 0;
    }
    sock = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
    if (sock < 0) {
        perror("creating socket");
        return 1;
    }
    l2addr.l2_family = AF_BLUETOOTH;
    l2addr.l2_cid = 4;
    l2addr.l2_bdaddr_type = BDADDR_LE_PUBLIC;
    if (bind(sock, (struct sockaddr *)&l2addr, sizeof(l2addr)) < 0) {
        perror("binding local socket");
        return 1;
    }
    l2addr.l2_family = AF_BLUETOOTH;
    str2ba(argv[1], &l2addr.l2_bdaddr);
    l2addr.l2_psm = 0;          // Unused for following CID
    l2addr.l2_cid = 4;          // reserved for ATTR exchanges
    l2addr.l2_bdaddr_type = BDADDR_LE_RANDOM;
    ba2str(&l2addr.l2_bdaddr, name);
    printf("Connecting to %s\n", name);
    if (connect(sock, (struct sockaddr *)&l2addr, sizeof(l2addr)) < 0) {
        perror("connecting socket");
        return 2;
    }
    puts("connected, hit return to exchange MTU sizes");
    getchar();
    out[0] = 0x02;
    out[1] = 0x00;
    out[2] = 0x02;
    if (transaction(sock, out, 3, in, sizeof(in), NULL) < 0) {
        goto oops;
    }
    puts("hit return to dump characteristics");
    getchar();
    uint16_t hnd = 0x0001;
    do {
        out[0] = 0x08;
        out[1] = (uint8_t)hnd;
        out[2] = (uint8_t)(hnd >> 8);
        out[3] = 0xff;
        out[4] = 0xff;
        out[5] = 0x03;
        out[6] = 0x28;
        if (transaction(sock, out, 7, in, sizeof(in), &hnd) < 0)
            goto oops;
        hnd += 1;
    } while (0x09 == in[0]);
    /*
    puts("hit return to dump values");
    getchar();
    for (uint16_t h=0x0001; h<hnd; h++) {
        out[0] = 0x0A;
        out[1] = (uint8_t)h;
        out[2] = (uint8_t)(h >> 8);
        if (transaction(sock, out, 3, in, sizeof(in), NULL) < 0)
            goto oops;
    }
    puts("hit return to read handle 0x001C continuously (Ctrl-C to stop)");
    getchar();
    signal(SIGINT, stop);
    while (!sigdone) {
        out[0] = 0x0A;
        out[1] = (uint8_t)0x1C;
        out[2] = 0;
        if (transaction(sock, out, 3, in, sizeof(in), NULL) < 0)
            goto oops;
    }
    */
    puts("hit, return to close");
    getchar();
oops:
    close(sock);
    return 0;
}

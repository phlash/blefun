#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>

void dumphex(char *pfx, uint8_t *buf, int len) {
    int i, j;
    for (i = 0; i < len; i+= 16) {
        printf(pfx);
        for (j = 0; j < 16 && (i+j) < len; j++)
            printf(" %02x", buf[i+j]);
        while (j++ < 16)
            printf("   ");
        printf("   ");
        for (j = 0; j < 16 && (i+j) < len; j++)
            printf("%c", isprint(buf[i+j]) ? buf[i+j] : '.');
        while (j++ < 16)
            printf(" ");
        printf("\n");
    }
}

int main(int argc, char **argv) {
    struct sockaddr_l2 l2addr = { 0 };
    char name[20];
    uint8_t buf[512];
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
    uint8_t mtu[3] = { 0x02, 0x00, 0x02 }; // We are good with up to 512 byte responses..
    if (write(sock, (char *)mtu, sizeof(mtu)) != sizeof(mtu)) {
        perror("writing MTU request");
        goto oops;
    }
    if (read(sock, (char *)mtu, sizeof(mtu)) != sizeof(mtu)) {
        perror("reading MTU response");
        goto oops;
    }
    printf("server MTU %02x %02x %02x\n", mtu[0], mtu[1], mtu[2]);
    puts("hit return to dump attributes");
    getchar();
    uint8_t find[5] = { 0x04, 0x01, 0x00, 0xff, 0xff };
    if (write(sock, (char *)find, sizeof(find)) != sizeof(find)) {
        perror("writing find request");
        goto oops;
    }
    nread = read(sock, buf, sizeof(buf));
    if (nread < 2) {
        perror("reading find response");
        goto oops;
    }
    printf("server find: %02x %02x\n", buf[0], buf[1]);
    int blk;
    switch (buf[1]) {
    case 0x01:
        blk = 4;
        break;
    case 0x02:
        blk = 18;
        break;
    default:
        fprintf(stderr, "invalid find response format\n");
        goto oops;
    }
    for (int i = 2; i < nread; i+= blk) {
        uint8_t val[512];
        if (4 == blk) {
            printf("\thnd=%02x%02x uuid=%02x%02x\n", buf[i+1], buf[i], buf[i+3], buf[i+2]);
        } else {
            printf("\thnd=%02x%02x uuid=");
            dumphex("", buf+i+2, 16);
        }
        uint8_t rdattr[3] = { 0x0A, buf[i], buf[i+1] };
        if (write(sock, rdattr, sizeof(rdattr)) != sizeof(rdattr)) {
            perror("writing read handle");
            goto oops;
        }
        int nval = read(sock, val, sizeof(val));
        if (nval < 1) {
            perror("reading handle value");
            goto oops;
        }
        dumphex("\tval: ", val+1, nval-1);
    }
    puts("hit, return to close");
    getchar();
oops:
    close(sock);
    return 0;
}

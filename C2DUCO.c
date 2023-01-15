/* C2DUCO - DuinoCoin minimal cpuminer in plain C89. By uint69_t */

#include <arpa/inet.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define SHA1ROTATELEFT(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

#define BUF_LEN 512
uint8_t buf[BUF_LEN];

struct hostcon {
    int sock;
    struct sockaddr_in addr;
};

struct job {
    uint8_t work[40];
    uint8_t expected[40];
    uint64_t diff;
};

void extract_between(char *in, char *p1, char *p2, char *out) {
    char *i1;

    uint16_t pl1;
    uint16_t mlen;

    i1 = strstr(in, p1);
    if (i1 != NULL) {
        pl1 = strlen(p1);
        if (p2 != NULL) {
            mlen = strstr(i1 + pl1, p2) - (i1 + pl1);
            memcpy(out, i1 + pl1, mlen);
            out[mlen] = '\0';
        }
    }
}

uint64_t str2u64(char *str) {
    uint64_t result = 0;

    while (str < str + strlen(str)) {
        result = (result << 1) + (result << 3) + *(str++) - '0';
    }

    return result;
}

void sha1digest(uint8_t *data, uint64_t databytes, char *hexdigest) {
    uint32_t W[80];
    uint32_t H[] = { 0x67452301,
                     0xEFCDAB89,
                     0x98BADCFE,
                     0x10325476,
                     0xC3D2E1F0 };
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f = 0;
    uint32_t k = 0;

    uint32_t idx;
    uint32_t lidx;
    uint32_t widx;
    uint32_t didx = 0;

    int32_t wcount;
    uint32_t temp;
    uint32_t loopcount = (databytes + 8) / 64 + 1;
    uint32_t tailbytes = 64 * loopcount - databytes;
    uint8_t datatail[128] = {0};

    if (!data || !hexdigest) {
        return;
    }

    /* Pre-processing of data tail (includes padding to fill out 512-bit chunk):
        Add bit '1' to end of message (big-endian)
        Add 64-bit message length in bits at very end (big-endian) */
    datatail[0] = 0x80;
    datatail[tailbytes - 8] = (uint8_t) ((databytes * 8) >> 56 & 0xFF);
    datatail[tailbytes - 7] = (uint8_t) ((databytes * 8) >> 48 & 0xFF);
    datatail[tailbytes - 6] = (uint8_t) ((databytes * 8) >> 40 & 0xFF);
    datatail[tailbytes - 5] = (uint8_t) ((databytes * 8) >> 32 & 0xFF);
    datatail[tailbytes - 4] = (uint8_t) ((databytes * 8) >> 24 & 0xFF);
    datatail[tailbytes - 3] = (uint8_t) ((databytes * 8) >> 16 & 0xFF);
    datatail[tailbytes - 2] = (uint8_t) ((databytes * 8) >> 8 & 0xFF);
    datatail[tailbytes - 1] = (uint8_t) ((databytes * 8) >> 0 & 0xFF);

    /* Process each 512-bit chunk */
    for (lidx = 0; lidx < loopcount; lidx++) {
        /* Compute all elements in W */
        memset(W, 0, 80 * sizeof(uint32_t));

        /* Break 512-bit chunk into sixteen 32-bit, big endian words */
        for (widx = 0; widx <= 15; widx++) {
            wcount = 24;

            /* Copy byte-per byte from specified buffer */
            while (didx < databytes && wcount >= 0) {
                W[widx] += (((uint32_t) data[didx]) << wcount);
                didx++;
                wcount -= 8;
            }

            /* Fill out W with padding as needed */
            while (wcount >= 0) {
                W[widx] += (((uint32_t) datatail[didx - databytes]) << wcount);
                didx++;
                wcount -= 8;
            }
        }

        /* Extend the sixteen 32-bit words into eighty 32-bit words, with potential optimization from:
        "Improving the Performance of the Secure Hash Algorithm (SHA-1)" by Max Locktyukhin */
        for (widx = 16; widx <= 31; widx++) {
            W[widx] = SHA1ROTATELEFT((W[widx - 3] ^ W[widx - 8] ^ W[widx - 14] ^ W[widx - 16]), 1);
        }

        for (widx = 32; widx <= 79; widx++) {
            W[widx] = SHA1ROTATELEFT((W[widx - 6] ^ W[widx - 16] ^ W[widx - 28] ^ W[widx - 32]), 2);
        }

        /* Main loop */
        a = H[0];
        b = H[1];
        c = H[2];
        d = H[3];
        e = H[4];

        for (idx = 0; idx <= 79; idx++) {
            if (idx <= 19) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (idx >= 20 && idx <= 39) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (idx >= 40 && idx <= 59) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else if (idx >= 60 && idx <= 79) {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            temp = SHA1ROTATELEFT(a, 5) + f + e + k + W[idx];
            e = d;
            d = c;
            c = SHA1ROTATELEFT(b, 30);
            b = a;
            a = temp;
        }

        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
    }

    sprintf(hexdigest, "%08x%08x%08x%08x%08x", H[0], H[1], H[2], H[3], H[4]);
}

int getpool(void) {
    struct hostcon server;
    struct hostcon pool;
    char pool_ip[16];
    char pool_port[6];

    server.sock = socket(AF_INET, SOCK_STREAM, 0);

    server.addr.sin_family = AF_INET;
    server.addr.sin_port = htons(80);
    server.addr.sin_addr.s_addr = inet_addr("51.15.127.80");

    connect(server.sock,
            (struct sockaddr *) &server.addr,
            sizeof(server.addr));
    
    strcpy((char *) buf, "GET /getPool HTTP/1.1\r\n"
                         "Host: 51.15.127.80\r\n"
                         "Content-Type: text/plain\r\n\r\n");

    send(server.sock, buf, 71, 0);
    memset(buf, 0, BUF_LEN);
    recv(server.sock, buf, BUF_LEN, 0);
    
    close(server.sock);

    extract_between((char *) buf, "\x22ip\x22:\x22", "\x22", pool_ip);
    extract_between((char *) buf, "\x22port\x22:", ",", pool_port);

    memset(buf, 0, BUF_LEN);

    pool.sock = socket(AF_INET, SOCK_STREAM, 0);

    pool.addr.sin_family = AF_INET;
    pool.addr.sin_port = htons(strtoul(pool_port, NULL, 10));
    pool.addr.sin_addr.s_addr = inet_addr(pool_ip);

    connect(pool.sock,
            (struct sockaddr *) &pool.addr,
            sizeof(pool.addr));

    return pool.sock;
}

void getjob(int sock, char *user, char *diff, char *key, struct job *job) {
    sprintf((char *) buf, "JOB,%s,%s,%s", user, diff, key);

    send(sock, buf, 10 + strlen(user) + strlen(key), 0);
    memset(buf, 0, BUF_LEN);
    recv(sock, buf, BUF_LEN, 0);

    memcpy(job->work, buf, 40);
    memcpy(job->expected, buf + 41, 40);
    job->diff = str2u64((char *) buf + 82);

    memset(buf, 0, BUF_LEN);
}

void sendjob(int sock, uint64_t hashrate, char *result) {
    sprintf((char *) buf, "%s,%" PRIu64 ",C2DUCO", result, hashrate);
	send(sock, buf, strlen((char *) buf), 0);
    memset(buf, 0, BUF_LEN);
	recv(sock, buf, BUF_LEN, 0);
}

int main(int argc, char **argv) {
    int sock;
    struct job job;
    uint64_t result;

    time_t start_t;
    time_t end_t;
    uint64_t hashrate;

    if (argc < 4) {
        printf("USAGE:\n");
        printf(" %s <user> <difficulty> <miningkey>\n", argv[0]);
        printf("EXAMPLE:\n");
        printf(" %s redminer03 HIGH None\n", argv[0]);
        printf(" %s 2001pc LOW oldpcpass\n", argv[0]);
        return 0;
    }

    sock = getpool();

    recv(sock, buf, BUF_LEN, 0);
    printf("Server version: %s", buf);
    memset(buf, 0, BUF_LEN);

    while (1) {
        getjob(sock, argv[1], argv[2], argv[3], &job);
        memcpy(buf, job.work, 40);

        time(&start_t);
        for (result = 0; result < 100 * job.diff + 1; result++) {
            sprintf((char *) buf + 40, "%" PRIu64, result);
            sha1digest(buf, strlen((char *) buf), (char *) buf + BUF_LEN - 40);
            if (memcmp(buf + BUF_LEN - 40, job.expected, 40) == 0) {
                time(&end_t);
                if (end_t - start_t <= 0) {
                    hashrate = result / 1;
                } else {
                    hashrate = result / (end_t - start_t);
                }

                sendjob(sock, hashrate, (char *) buf + 40);
                printf("Found! diff: %" PRIu64 ", hashrate: %" PRIu64 " -> %s",
                       job.diff, hashrate, buf);
                       
				break;
			}
        }
    }

    return 0;
}
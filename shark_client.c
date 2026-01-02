#include <liburing.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <time.h>

#define MAX_PKG_LEN 65535
#define MAX_CONN    32
#define POOL_SIZE   2048

struct pkt_header { uint32_t len; uint64_t seq; } __attribute__((packed));
struct buf_node { uint8_t data[MAX_PKG_LEN]; uint32_t len; uint64_t seq; int used; };
struct conn_ctx { int fd; char ip[64]; int port; uint8_t *wbuf; int wlen; uint8_t *rbuf; struct pkt_header head; int stage; int active; };

static struct buf_node *rx_pool = NULL;
static uint64_t client_expect_seq = 0, client_tx_seq = 0;

void xor_crypt(uint8_t *data, int len) {
    uint32_t key = 0x5AA55AA5;
    for (int i = 0; i < len; i++) data[i] ^= ((uint8_t*)&key)[i % 4];
}

void flush_to_tun(int tun_fd) {
    while (1) {
        int slot = client_expect_seq % POOL_SIZE;
        if (rx_pool[slot].used && rx_pool[slot].seq == client_expect_seq) {
            write(tun_fd, rx_pool[slot].data, rx_pool[slot].len);
            rx_pool[slot].used = 0; client_expect_seq++;
        } else break;
    }
}

int try_connect(struct conn_ctx *ctx, struct io_uring *ring, int idx) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in saddr = {.sin_family = AF_INET, .sin_port = htons(ctx->port), .sin_addr.s_addr = inet_addr(ctx->ip)};
    
    // 限制缓冲区与超时设置
    int nodelay = 1, buf_size = 65535, to = 1500, lowat = 16384;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, 4);
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf_size, 4);
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf_size, 4);
    setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &to, 4);
    setsockopt(fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &lowat, 4);

    if (connect(fd, (struct sockaddr*)&saddr, sizeof(saddr)) == 0) {
        fcntl(fd, F_SETFL, O_NONBLOCK); ctx->fd = fd; ctx->active = 1; ctx->stage = 0; ctx->wlen = 0;
        struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
        io_uring_prep_read(sqe, fd, &ctx->head, 12, 0); sqe->user_data = idx;
        return 1;
    }
    close(fd); return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 5) return 1;
    rx_pool = calloc(POOL_SIZE, sizeof(struct buf_node));
    struct conn_ctx *ctxs = calloc(MAX_CONN, sizeof(struct conn_ctx));
    for(int i=0; i<MAX_CONN; i++) { ctxs[i].wbuf = malloc(MAX_PKG_LEN+16); ctxs[i].rbuf = malloc(MAX_PKG_LEN); }
    
    int tun_fd = open("/dev/net/tun", O_RDWR);
    struct ifreq ifr = {.ifr_flags = IFF_TUN | IFF_NO_PI}; strncpy(ifr.ifr_name, argv[3], IFNAMSIZ);
    ioctl(tun_fd, TUNSETIFF, &ifr); fcntl(tun_fd, F_SETFL, O_NONBLOCK);

    struct io_uring ring; io_uring_queue_init(1024, &ring, 0);
    char *ips_copy = strdup(argv[1]);
    char *ip_ptr = strtok(ips_copy, ",");
    int total = 0, per_ip = atoi(argv[4]);
    while(ip_ptr) {
        for(int i=0; i<per_ip && total < MAX_CONN; i++) {
            strcpy(ctxs[total].ip, ip_ptr); ctxs[total].port = atoi(argv[2]);
            try_connect(&ctxs[total], &ring, total); total++;
        }
        ip_ptr = strtok(NULL, ",");
    }

    static uint8_t tun_rx[MAX_PKG_LEN];
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_read(sqe, tun_fd, tun_rx, MAX_PKG_LEN, 0); sqe->user_data = 0xFFFFF;
    io_uring_submit(&ring);

    time_t last_reconnect = 0;
    while(1) {
        struct io_uring_cqe *cqe;
        struct __kernel_timespec ts = {.tv_sec = 0, .tv_nsec = 100000000};
        int ret = io_uring_wait_cqe_timeout(&ring, &cqe, &ts);
        
        time_t now = time(NULL);
        if (now - last_reconnect > 5) {
            for(int i=0; i<total; i++) if(!ctxs[i].active) try_connect(&ctxs[i], &ring, i);
            last_reconnect = now;
        }

        if (ret < 0) { io_uring_submit(&ring); continue; }
        uint64_t tag = cqe->user_data;
        if (tag == 0xFFFFF) {
            if (cqe->res > 0) {
                struct pkt_header h = {htonl(cqe->res), client_tx_seq++};
                for(int i=0; i<total; i++) if(ctxs[i].active && ctxs[i].wlen == 0) {
                    memcpy(ctxs[i].wbuf, &h, 12); memcpy(ctxs[i].wbuf+12, tun_rx, cqe->res);
                    xor_crypt(ctxs[i].wbuf+12, cqe->res); ctxs[i].wlen = 12 + cqe->res;
                    sqe = io_uring_get_sqe(&ring);
                    io_uring_prep_write(sqe, ctxs[i].fd, ctxs[i].wbuf, ctxs[i].wlen, 0); sqe->user_data = 0x10000+i;
                }
            }
            sqe = io_uring_get_sqe(&ring); io_uring_prep_read(sqe, tun_fd, tun_rx, MAX_PKG_LEN, 0); sqe->user_data = 0xFFFFF;
        } else if (tag >= 0x10000) ctxs[tag-0x10000].wlen = 0;
        else {
            int idx = (int)tag;
            if (cqe->res <= 0) { ctxs[idx].active = 0; close(ctxs[idx].fd); ctxs[idx].fd = -1; }
            else if (ctxs[idx].stage == 0) {
                ctxs[idx].head.len = ntohl(ctxs[idx].head.len); ctxs[idx].stage = 1;
                sqe = io_uring_get_sqe(&ring); io_uring_prep_read(sqe, ctxs[idx].fd, ctxs[idx].rbuf, ctxs[idx].head.len, 0); sqe->user_data = tag;
            } else {
                xor_crypt(ctxs[idx].rbuf, ctxs[idx].head.len);
                if (ctxs[idx].head.seq >= client_expect_seq) {
                    int slot = ctxs[idx].head.seq % POOL_SIZE;
                    if (!rx_pool[slot].used) {
                        memcpy(rx_pool[slot].data, ctxs[idx].rbuf, ctxs[idx].head.len);
                        rx_pool[slot].len = ctxs[idx].head.len;
                        rx_pool[slot].seq = ctxs[idx].head.seq; rx_pool[slot].used = 1;
                        flush_to_tun(tun_fd);
                    }
                }
                ctxs[idx].stage = 0;
                sqe = io_uring_get_sqe(&ring); io_uring_prep_read(sqe, ctxs[idx].fd, &ctxs[idx].head, 12, 0); sqe->user_data = tag;
            }
        }
        io_uring_cqe_seen(&ring, cqe); io_uring_submit(&ring);
    }
}

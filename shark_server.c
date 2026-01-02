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

#define MAX_PKG_LEN 65535
#define MAX_CONN    32
#define POOL_SIZE   2048

struct pkt_header { uint32_t len; uint64_t seq; } __attribute__((packed));
struct buf_node { uint8_t data[MAX_PKG_LEN]; uint32_t len; uint64_t seq; int used; };
struct conn_ctx { int fd; uint8_t *wbuf; int wlen; uint8_t *rbuf; struct pkt_header head; int stage; int active; };

static struct buf_node *rx_pool = NULL;
static uint64_t server_expect_seq = 0, server_tx_seq = 0;

void xor_crypt(uint8_t *data, int len) {
    uint32_t key = 0x5AA55AA5;
    for (int i = 0; i < len; i++) data[i] ^= ((uint8_t*)&key)[i % 4];
}

void flush_to_tun(int tun_fd) {
    while (1) {
        int slot = server_expect_seq % POOL_SIZE;
        if (rx_pool[slot].used && rx_pool[slot].seq == server_expect_seq) {
            write(tun_fd, rx_pool[slot].data, rx_pool[slot].len);
            rx_pool[slot].used = 0; server_expect_seq++;
        } else break;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) return 1;
    rx_pool = calloc(POOL_SIZE, sizeof(struct buf_node));
    struct conn_ctx *ctxs = calloc(MAX_CONN, sizeof(struct conn_ctx));
    for(int i=0; i<MAX_CONN; i++) {
        ctxs[i].fd = -1;
        ctxs[i].wbuf = malloc(MAX_PKG_LEN + 16);
        ctxs[i].rbuf = malloc(MAX_PKG_LEN);
    }

    int tun_fd = open("/dev/net/tun", O_RDWR);
    struct ifreq ifr = {.ifr_flags = IFF_TUN | IFF_NO_PI};
    strncpy(ifr.ifr_name, argv[2], IFNAMSIZ);
    ioctl(tun_fd, TUNSETIFF, &ifr);
    fcntl(tun_fd, F_SETFL, O_NONBLOCK);

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(atoi(argv[1])), .sin_addr.s_addr = INADDR_ANY};
    int opt = 1; setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, 4);
    bind(lfd, (struct sockaddr*)&addr, sizeof(addr)); listen(lfd, 32);

    struct io_uring ring; io_uring_queue_init(1024, &ring, 0);
    static uint8_t tun_rx[MAX_PKG_LEN];
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_read(sqe, tun_fd, tun_rx, MAX_PKG_LEN, 0); sqe->user_data = 0xFFFFF;

    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_accept(sqe, lfd, NULL, NULL, 0); sqe->user_data = 0xAAAAA;
    io_uring_submit(&ring);

    while (1) {
        struct io_uring_cqe *cqe; io_uring_wait_cqe(&ring, &cqe);
        uint64_t tag = cqe->user_data;

        if (tag == 0xFFFFF) {
            if (cqe->res > 0) {
                struct pkt_header h = {htonl(cqe->res), server_tx_seq++};
                for (int i=0; i<MAX_CONN; i++) {
                    // 仅向未积压数据的通道发送冗余包
                    if (ctxs[i].active && ctxs[i].wlen == 0) {
                        memcpy(ctxs[i].wbuf, &h, 12); memcpy(ctxs[i].wbuf+12, tun_rx, cqe->res);
                        xor_crypt(ctxs[i].wbuf+12, cqe->res); ctxs[i].wlen = 12 + cqe->res;
                        sqe = io_uring_get_sqe(&ring);
                        io_uring_prep_write(sqe, ctxs[i].fd, ctxs[i].wbuf, ctxs[i].wlen, 0);
                        sqe->user_data = 0x10000 + i;
                    }
                }
            }
            sqe = io_uring_get_sqe(&ring);
            io_uring_prep_read(sqe, tun_fd, tun_rx, MAX_PKG_LEN, 0); sqe->user_data = 0xFFFFF;
        } else if (tag == 0xAAAAA) {
            int cfd = cqe->res;
            if (cfd > 0) {
                int s = -1; for(int i=0; i<MAX_CONN; i++) if(ctxs[i].fd == -1){s=i; break;}
                if(s != -1) {
                    ctxs[s].fd = cfd; ctxs[s].active = 1; ctxs[s].wlen = 0; ctxs[s].stage = 0;
                    // --- 底层低延迟属性调优 ---
                    int nodelay = 1, buf_size = 65535, to = 1500, lowat = 16384;
                    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &nodelay, 4);
                    setsockopt(cfd, SOL_SOCKET, SO_SNDBUF, &buf_size, 4);
                    setsockopt(cfd, SOL_SOCKET, SO_RCVBUF, &buf_size, 4);
                    setsockopt(cfd, IPPROTO_TCP, TCP_USER_TIMEOUT, &to, 4);
                    setsockopt(cfd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &lowat, 4);

                    sqe = io_uring_get_sqe(&ring);
                    io_uring_prep_read(sqe, cfd, &ctxs[s].head, 12, 0); sqe->user_data = s;
                } else close(cfd);
            }
            sqe = io_uring_get_sqe(&ring); io_uring_prep_accept(sqe, lfd, NULL, NULL, 0); sqe->user_data = 0xAAAAA;
        } else {
            int idx = (tag >= 0x10000) ? (tag - 0x10000) : tag;
            if (tag < 0x10000) {
                if (cqe->res <= 0) { close(ctxs[idx].fd); ctxs[idx].fd = -1; ctxs[idx].active = 0; }
                else if (ctxs[idx].stage == 0) {
                    ctxs[idx].head.len = ntohl(ctxs[idx].head.len); ctxs[idx].stage = 1;
                    sqe = io_uring_get_sqe(&ring);
                    io_uring_prep_read(sqe, ctxs[idx].fd, ctxs[idx].rbuf, ctxs[idx].head.len, 0); sqe->user_data = idx;
                } else {
                    xor_crypt(ctxs[idx].rbuf, ctxs[idx].head.len);
                    if (ctxs[idx].head.seq >= server_expect_seq) {
                        int slot = ctxs[idx].head.seq % POOL_SIZE;
                        if (!rx_pool[slot].used) {
                            memcpy(rx_pool[slot].data, ctxs[idx].rbuf, ctxs[idx].head.len);
                            rx_pool[slot].len = ctxs[idx].head.len;
                            rx_pool[slot].seq = ctxs[idx].head.seq; rx_pool[slot].used = 1;
                            flush_to_tun(tun_fd);
                        }
                    }
                    ctxs[idx].stage = 0;
                    sqe = io_uring_get_sqe(&ring);
                    io_uring_prep_read(sqe, ctxs[idx].fd, &ctxs[idx].head, 12, 0); sqe->user_data = idx;
                }
            } else ctxs[idx].wlen = 0;
        }
        io_uring_cqe_seen(&ring, cqe); io_uring_submit(&ring);
    }
}

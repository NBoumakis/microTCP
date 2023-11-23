/*
 * microtcp, a lightweight implementation of TCP for teaching,
 * and academic purposes.
 *
 * Copyright (C) 2015-2017  Manolis Surligas <surligas@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "microtcp.h"
#include "../utils/crc32.h"
#include <errno.h>
#include <netinet/ip.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define DEBUG

#define ACK (1 << 12)
#define RST (1 << 13)
#define SYN (1 << 14)
#define FIN (1 << 15)

#ifdef DEBUG
static void debugInfo(microtcp_sock_t *socket) {
    printf("Ack number: %lu\n", socket->ack_number);
    printf("Seq number: %lu\n", socket->seq_number);

    printf("ssthresh: %lu\n", socket->ssthresh);
    printf("cwnd: %lu (%lu MSS) \n", socket->cwnd, socket->cwnd / MICROTCP_MSS);

    printf("Fill level: %lu\n", socket->buf_fill_level);
    printf("Bytes sent/received/lost: %lu/%lu/%lu\n", socket->bytes_send, socket->bytes_received, socket->bytes_lost);

    printf("Init win size: %lu\n", socket->init_win_size);
    printf("Curr win size: %lu\n", socket->curr_win_size);

    printf("Packets sent/received/lost: %lu/%lu/%lu\n", socket->packets_send, socket->packets_received, socket->packets_lost);

    printf("\n");
}
#endif

static int check_checksum_header(microtcp_header_t *);
static int check_checksum_packet(uint8_t *, uint32_t, uint32_t);
static void update_congestion_control(microtcp_sock_t *, int, int, size_t);
static size_t roundUp(size_t, size_t);

size_t min2(size_t a, size_t b) {
    if (a < b)
        return a;
    else
        return b;
}

size_t min3(size_t a, size_t b, size_t c) {
    size_t result = min2(a, b);

    return min2(result, c);
}

static void packet_header(microtcp_header_t *header, uint32_t seq_number,
                          uint32_t ack_number, int ack, int rst, int syn,
                          int fin, uint16_t window, uint32_t data_len,
                          uint32_t future_use0, uint32_t future_use1,
                          uint32_t future_use2, uint32_t checksum);

microtcp_sock_t microtcp_socket(int domain, int type, int protocol) {
    microtcp_sock_t sock;
    srand(time(NULL));

    sock.state = UNKNOWN;

    sock.seq_number = random();

    sock.sd = socket(domain, SOCK_DGRAM, 0);

    if (sock.sd == -1) {
        sock.state = INVALID;
    }

    sock.cwnd = MICROTCP_INIT_CWND;
    sock.ssthresh = MICROTCP_INIT_SSTHRESH;

    sock.packets_lost = 0;
    sock.packets_received = 0;
    sock.packets_send = 0;

    sock.bytes_lost = 0;
    sock.bytes_received = 0;
    sock.bytes_send = 0;

    sock.buf_fill_level = 0;

    return sock;
}

int microtcp_bind(microtcp_sock_t *socket, const struct sockaddr *address,
                  socklen_t address_len) {
    if (socket->state == INVALID)
        return -1;

    int strue = 1;
    setsockopt(socket->sd, SOL_SOCKET, SO_REUSEADDR, &strue, sizeof(strue));

    if (bind(socket->sd, address, address_len) < 0) {
        return -1;
    }

    socket->state = LISTEN;

    return 0;
}

int microtcp_connect(microtcp_sock_t *socket, const struct sockaddr *address,
                     socklen_t address_len) {
    microtcp_header_t header;

    if (socket->state == INVALID)
        return -1;

    if (connect(socket->sd, address, address_len) == -1) {
        return -1;
    }

    /*send packet SYN*/
    packet_header(&header, socket->seq_number, 0, 0, 0, 1, 0, MICROTCP_WIN_SIZE, 0, 0, 0, 0, 0);
    header.checksum = crc32((const uint8_t *)&header, sizeof(header));
    if (send(socket->sd, &header, sizeof(header), 0) < 0) {
        printf("Error: 3-way handshake: SYN: Send packet\n");
        return -1;
    }
    ++socket->seq_number;

    struct timeval timeout = {.tv_sec = 0, .tv_usec = MICROTCP_ACK_TIMEOUT_US};
    if (setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(struct timeval)) < 0) {
        perror(" setsockopt ");
        return -1;
    }

    /*receive packet SYN-ACK */
    if (recv(socket->sd, &header, sizeof(header), 0) < 0) {
        printf("Error: 3-way handshake: SYN,ACK: Receive packet\n");
        return -1;
    }

    timeout.tv_usec = 0;
    if (setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(struct timeval)) < 0) {
        perror(" setsockopt ");
        return -1;
    }

    if (check_checksum_header(&header)) {
        printf("Error: 3-way handshake: SYN,ACK: Checksum\n");
        return -1;
    }

    /*elegxos Ack number poy elaba*/
    if (socket->seq_number != header.ack_number) {
        printf("Error: 3-way handshake: SYN,ACK: Ack number\n");
        return -1;
    }

    /*elegxos gia ACK=1 kai SYN=1*/
    if (header.control != (SYN | ACK)) {
        printf("Error 3-way handshake: SYN,ACK: Control fields\n");
        return -1;
    }

    socket->init_win_size = header.window;
    socket->curr_win_size = header.window;
    socket->ack_number = header.seq_number + 1;

    /*send ACK sto SYN-ACK*/
    packet_header(&header, socket->seq_number, socket->ack_number, 1, 0, 0, 0, MICROTCP_WIN_SIZE, 0, 0, 0, 0, 0);
    header.checksum = crc32((const uint8_t *)&header, sizeof(header));
    if (send(socket->sd, &header, sizeof(header), 0) < 0) {
        printf("Error: 3-way handshake: ACK: Send packet\n");
        return -1;
    }

    ++socket->seq_number;

    /*allocated buffer*/
    socket->recvbuf = (uint8_t *)malloc(sizeof(uint8_t) * MICROTCP_RECVBUF_LEN);
    socket->state = ESTABLISHED;

    return 0;
}

int microtcp_accept(microtcp_sock_t *socket, struct sockaddr *address,
                    socklen_t address_len) {

    microtcp_header_t header;

    if (socket->state == INVALID) {
        printf("Socket invalid!\n");
        return -1;
    }

    /*receive SYN=1, seq=N HEADER*/
    if (recvfrom(socket->sd, &header, sizeof(header), 0, address, &address_len) == -1) {
        printf("Error: 3-way handshake: SYN: Receive packet\n");
        return -1;
    }

    if (check_checksum_header(&header)) {
        printf("Error: 3-way handshake: SYN: Checksum\n");
        return -1;
    }

    if (header.control != SYN) { // check SYN sent from client
        printf("Error: 3-way handshake: SYN: Control field\n");
        return -1;
    }

    socket->ack_number = header.seq_number + 1;

    packet_header(&header, socket->seq_number, socket->ack_number, 1, 0, 1, 0, MICROTCP_WIN_SIZE, 0, 0, 0, 0, 0);
    header.checksum = crc32((const uint8_t *)&header, sizeof(header));

    /*send SYN=1, ACK=1 from control, seq=M,ack=N+1 HEADER*/
    if (sendto(socket->sd, &header, sizeof(header), 0, address, address_len) == -1) {
        printf("Error: 3-way handshake: SYN,ACK: Send packet\n");
        return -1;
    }
    ++socket->seq_number;

    struct timeval timeout = {.tv_sec = 0, .tv_usec = MICROTCP_ACK_TIMEOUT_US};
    if (setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(struct timeval)) < 0) {
        perror(" setsockopt ");
        return -1;
    }

    /*receive ACK=1 from control, seq=N+1,ack=M+1 HEADER*/
    if (recvfrom(socket->sd, &header, sizeof(header), 0, address, &address_len) == -1) {
        printf("Error: 3-way handshake: ACK: Receive packet\n");
        return -1;
    }

    timeout.tv_usec = 0;
    if (setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(struct timeval)) < 0) {
        perror(" setsockopt ");
        return -1;
    }

    if (check_checksum_header(&header)) {
        printf("Error: 3-way handshake: ACK: Checksum\n");
        return -1;
    }

    if (header.control != ACK) { // check ACK from client, second packet recv
        printf("Error: 3-way handshake: ACK: Control fields\n");
        return -1;
    }

    if (header.seq_number != socket->ack_number) { // N+1 from header equals seq+1 that server sent
        printf("Error: 3-way handshake: ACK: Seq number\n");
        return -1;
    }

    if (header.ack_number != socket->seq_number) { // M+1 from header equals ack that server sent
        printf("Error: 3-way handshake: ACK: Ack number\n");
        return -1;
    }

    connect(socket->sd, address, address_len);

    ++socket->ack_number;
    socket->curr_win_size = header.window;
    socket->init_win_size = header.window;

    socket->recvbuf = (uint8_t *)malloc(sizeof(uint8_t) * MICROTCP_RECVBUF_LEN);

    return 0; // return 0 for success
}

int microtcp_shutdown(microtcp_sock_t *socket, int how) {
    microtcp_header_t header;

    if (socket->state == CLOSING_BY_PEER) {
        // Server side confirmed, packet FIN,ACK handled by microtcp_recv
        ++socket->ack_number;
        packet_header(&header, socket->seq_number, socket->ack_number, 1, 0, 0,
                      0, MICROTCP_WIN_SIZE, 0, 0, 0, 0, 0);
        header.checksum = crc32((const uint8_t *)&header, sizeof(header));

        if (send(socket->sd, &header, sizeof(microtcp_header_t), 0) < 0) {
            printf("Error: Shutdown handshake: ACK: Send packet\n");
            return -1;
        }
        ++socket->seq_number;

        packet_header(&header, socket->seq_number, socket->ack_number, 1, 0, 0, 1,
                      MICROTCP_WIN_SIZE, 0, 0, 0, 0, 0);
        header.checksum = crc32((const uint8_t *)&header, sizeof(header));

        if (send(socket->sd, &header, sizeof(microtcp_header_t), 0) < 0) {
            printf("Error: Shutdown handshake: FIN,ACK: Send packet\n");
            return -1;
        }
        ++socket->seq_number;

        struct timeval timeout = {.tv_sec = 0, .tv_usec = MICROTCP_ACK_TIMEOUT_US};
        if (setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                       sizeof(struct timeval)) < 0) {
            perror(" setsockopt ");
            return -1;
        }

        if (recv(socket->sd, &header, sizeof(microtcp_header_t), 0) < 0) {
            printf("Error: Shutdown handshake: ACK: Receive packet\n");
            return -1;
        }

        timeout.tv_usec = 0;
        if (setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                       sizeof(struct timeval)) < 0) {
            perror(" setsockopt ");
            return -1;
        }

        if (check_checksum_header(&header)) {
            printf("Error: Shutdown handshake: ACK: Checksum\n");
            return -1;
        }

        if (header.control != ACK) {
            printf("Error: Shutdown handshake: ACK: Control fields\n");
            return -1;
        }

        if (socket->ack_number != header.seq_number) {
            printf("Error: Shutdown handshake: ACK: Seq number\n");
            return -1;
        }

        if (socket->seq_number != header.ack_number) {
            printf("Error: Shutdown handshake: ACK: Ack number\n");
            return -1;
        }
    } else if (socket->state == ESTABLISHED) {
        // Invoked by client
        packet_header(&header, socket->seq_number, socket->ack_number, 1, 0, 0, 1,
                      MICROTCP_WIN_SIZE, 0, 0, 0, 0, 0);
        header.checksum = crc32((const uint8_t *)&header, sizeof(header));

        if (send(socket->sd, &header, sizeof(microtcp_header_t), 0) < 0) {
            printf("Error: Shutdown handshake: FIN,ACK: Send number\n");
            return -1;
        }
        ++socket->seq_number;
        struct timeval timeout = {.tv_sec = 0, .tv_usec = MICROTCP_ACK_TIMEOUT_US};
        if (setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                       sizeof(struct timeval)) < 0) {
            perror(" setsockopt ");
            return -1;
        }

        if (recv(socket->sd, &header, sizeof(microtcp_header_t), 0) < 0) {
            printf("Error: Shutdown handshake: ACK: Receive packet\n");
            return -1;
        }

        if (check_checksum_header(&header)) {
            printf("Error: Shutdown handshake: ACK: Checksum\n");
            return -1;
        }

        if (header.control != ACK) {
            printf("Error: Shutdown handshake: ACK: Control fields\n");
            return -1;
        }
        // Expect header.ack = X+1 == SEQ
        if (socket->seq_number != header.ack_number) {
            printf("Error: Shutdown handshake: ACK: Ack number\n");
            return -1;
        }

        socket->state = CLOSING_BY_HOST;

        if (recv(socket->sd, &header, sizeof(microtcp_header_t), 0) < 0) {
            printf("Error: Shutdown handshake: FIN,ACK: Receive packet\n");
            return -1;
        }

        timeout.tv_usec = 0;
        if (setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                       sizeof(struct timeval)) < 0) {
            perror(" setsockopt ");
            return -1;
        }

        if (check_checksum_header(&header)) {
            printf("Error: Shutdown handshake: ACK: Checksum\n");
            return -1;
        }

        if (header.control != (ACK | FIN)) {
            printf("Error: Shutdown handshake: ACK: Control fields\n");
            return -1;
        }
        socket->ack_number = header.seq_number + 1;

        packet_header(&header, socket->seq_number, socket->ack_number, 1, 0, 0, 0,
                      MICROTCP_WIN_SIZE, 0, 0, 0, 0, 0);
        header.checksum = crc32((const uint8_t *)&header, sizeof(header));

        if (send(socket->sd, &header, sizeof(microtcp_header_t), 0) < 0) {
            printf("Error: Shutdown handshake: ACK: Send packet\n");
            return -1;
        }
    }

    free(socket->recvbuf);
    close(socket->sd); // Syscall

    socket->state = CLOSED;

    return 0;
}

ssize_t microtcp_send(microtcp_sock_t *socket, const void *buffer,
                      size_t length, int flags) {
    size_t remaining, data_sent = 0, bytes_to_send = 0, chunks_count = 0, i = 0,
                      chunk_size = 0, max_ack = 0, init_seq = socket->seq_number, transmission_cwnd;
    uint8_t *chunk;
    uint8_t duplicate_ack = 0;
    microtcp_header_t header;
    struct timeval timeout = {.tv_sec = 0, .tv_usec = MICROTCP_ACK_TIMEOUT_US};

    remaining = length;
    while (data_sent < length) {
        transmission_cwnd = socket->cwnd;

#ifdef DEBUG
        printf("=======Transmission round=======\n");

        printf("Before transmission\n");
        debugInfo(socket);
#endif

        bytes_to_send = min3(socket->curr_win_size, transmission_cwnd, remaining);
        chunks_count = bytes_to_send / MICROTCP_MSS;

        chunk_size = MICROTCP_MSS + sizeof(microtcp_header_t);
        chunk = malloc(chunk_size);

        for (i = 0; i < chunks_count; i++) {
            packet_header(&header, socket->seq_number, socket->ack_number, 0, 0, 0, 0,
                          socket->init_win_size - socket->buf_fill_level, MICROTCP_MSS, 0, 0, 0, 0);

            memcpy(chunk, &header, sizeof(microtcp_header_t));
            memcpy(chunk + sizeof(microtcp_header_t),
                   buffer + (socket->seq_number - init_seq), MICROTCP_MSS);

            header.checksum = crc32(chunk, chunk_size);
            memcpy(chunk, &header, sizeof(microtcp_header_t));

            send(socket->sd, chunk, chunk_size, flags);

            socket->seq_number += MICROTCP_MSS;
        }

        free(chunk);

        /* Check if there is a semi - filled chunk */
        if (bytes_to_send % MICROTCP_MSS) {
            chunks_count++;

            chunk_size = (bytes_to_send % MICROTCP_MSS) + sizeof(microtcp_header_t);
            chunk = malloc(chunk_size);

            packet_header(&header, socket->seq_number, socket->ack_number, 0, 0, 0, 0,
                          socket->init_win_size - socket->buf_fill_level, bytes_to_send % MICROTCP_MSS, 0, 0, 0, 0);

            memcpy(chunk, &header, sizeof(microtcp_header_t));
            memcpy(chunk + sizeof(microtcp_header_t),
                   buffer + (socket->seq_number - init_seq),
                   bytes_to_send % MICROTCP_MSS);

            header.checksum = crc32(chunk, chunk_size);
            memcpy(chunk, &header, sizeof(microtcp_header_t));

            send(socket->sd, chunk, chunk_size, flags);

            socket->seq_number += bytes_to_send % MICROTCP_MSS;

            free(chunk);
        }

        /* Those chunks are header only and are used to find out when the congestion window stops being 0.
         * Causes problems, disabled */
        /* while (chunks_count < min2(transmission_cwnd / MICROTCP_MSS, roundUp(remaining, MICROTCP_MSS) / MICROTCP_MSS)) {
            packet_header(&header, socket->seq_number, socket->ack_number, 0, 0, 0, 0,
                          socket->init_win_size - socket->buf_fill_level, 0, 1, 0, 0, 0);

            header.checksum = crc32(&header, sizeof(microtcp_header_t));

            send(socket->sd, &header, sizeof(microtcp_header_t), flags);
            perror("CC packets");
            ++chunks_count;
        }*/

        /* Get the ACKs */
        if (setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                       sizeof(struct timeval)) < 0) {
            perror(" setsockopt ");
        }

        for (i = 0; i < chunks_count && max_ack < socket->seq_number; i++) {
            ssize_t rcv_ret = recv(socket->sd, &header, sizeof(microtcp_header_t), 0);

            if (rcv_ret != -1) {
                if (max_ack < header.ack_number) {
                    max_ack = header.ack_number;
                    duplicate_ack = 0;

                    update_congestion_control(socket, 0, duplicate_ack, transmission_cwnd);

#ifdef DEBUG
                    printf("Duplicate ACK %d\n", duplicate_ack);

                    printf("Normal %ld\n", remaining);
                    printf("Max ack %ld\n", max_ack);
                    printf("Ack: %d", header.ack_number);

                    debugInfo(socket);
#endif
                } else if (max_ack == header.ack_number && header.future_use0 == 0) {
                    if (++duplicate_ack == 3) {
                        update_congestion_control(socket, 0, duplicate_ack, transmission_cwnd);

#ifdef DEBUG
                        printf("3-duplicate ack\n");
                        printf("Max ack %ld\n", max_ack);
                        debugInfo(socket);
#endif

                        break;
                    }

#ifdef DEBUG
                    printf("Duplicate ACK %d\n", duplicate_ack);
                    printf("Max ack %ld\n", max_ack);
                    printf("Ack: %d\n", header.ack_number);
                    debugInfo(socket);
#endif
                } else if (max_ack == header.ack_number && header.future_use0 == 1) {

#ifdef DEBUG
                    printf("CC packet - Duplicate ACK %d\n", duplicate_ack);
                    printf("Max ack %ld\n", max_ack);
                    printf("Ack: %d", header.ack_number);
                    debugInfo(socket);
#endif
                }
            } else {
                duplicate_ack = 0;

                update_congestion_control(socket, 1, 0, transmission_cwnd);

#ifdef DEBUG
                printf("Timeout %ld\n", remaining);
                printf("Max ack %ld\n", max_ack);
                printf("%d, EINVAL: %d", errno, EWOULDBLOCK);

                debugInfo(socket);
#endif
                break;
            }
        }

        /* Retransmissions */
        /* Update window */
        /* Update congestion control */
        socket->cwnd = roundUp(socket->cwnd, MICROTCP_MSS);
        if (max_ack != 0) {
            socket->seq_number = max_ack;
            remaining = length - (max_ack - init_seq);
            data_sent = max_ack - init_seq;
        }
        /* XX */
    }

    timeout.tv_usec = 0;
    if (setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(struct timeval)) < 0) {
        perror(" setsockopt ");
    }

    return data_sent;
}

ssize_t microtcp_recv(microtcp_sock_t *socket, void *buffer, size_t length,
                      int flags) {
    ssize_t received = 0, data_recv = 0, to_user_size;
    uint8_t *packet, *payload;
    uint32_t tmp_checksum;
    microtcp_header_t *header;
    struct pollfd plfd[1];

    if (socket->state == CLOSING_BY_PEER) {
        return -1;
    }

    plfd[0].fd = socket->sd;
    plfd[0].events = POLLIN;

    /* Allocate space for the whole packet */
    packet = malloc(MICROTCP_MSS + sizeof(microtcp_header_t));

    if (packet == NULL) {
        printf("Malloc failed\n");
        return -1;
    }

#ifdef DEBUG
    printf("========Receive round========\n");
#endif
    do {
        data_recv = recv(socket->sd, packet, MICROTCP_MSS + sizeof(microtcp_header_t), 0);

#ifdef DEBUG
        printf("After receive packet\n");
        printf("Errno: %d\n", errno);

        debugInfo(socket);
#endif
        /* Pointer to the start of the packet payload */
        payload = packet + sizeof(microtcp_header_t);

        header = (microtcp_header_t *)packet;

        tmp_checksum = header->checksum;
        header->checksum = 0;

        data_recv -= sizeof(microtcp_header_t);

        if (header->seq_number == socket->ack_number && data_recv == header->data_len &&
            check_checksum_packet(packet, header->data_len + sizeof(microtcp_header_t), tmp_checksum)) {
            memcpy(socket->recvbuf + socket->buf_fill_level, payload, header->data_len);
            received += data_recv;
            socket->buf_fill_level += header->data_len;
            socket->ack_number += header->data_len;

            ++socket->packets_received;

            if (header->control == (FIN | ACK)) {
                socket->state = CLOSING_BY_PEER;
                break;
            }
        } else {
            ++socket->packets_lost;
        }

        packet_header(header, socket->seq_number, socket->ack_number, 1, 0, 0, 0, socket->init_win_size - socket->buf_fill_level, 0, header->future_use0, 0, 0, 0);
        header->checksum = crc32((const uint8_t *)header, sizeof(microtcp_header_t));
        send(socket->sd, header, sizeof(microtcp_header_t), 0);

#ifdef DEBUG
        printf("After send Ack\n");
        printf("Errno: %d\n", errno);

        debugInfo(socket);
#endif
    } while (received <= length && (poll(plfd, 1, 0) > 0 || socket->buf_fill_level == 0));

    to_user_size = min2(socket->buf_fill_level, length);

    memcpy(buffer, socket->recvbuf, to_user_size);
    memmove(socket->recvbuf, socket->recvbuf + to_user_size, socket->buf_fill_level - to_user_size);

    socket->buf_fill_level -= to_user_size;
    free(packet);
    packet = NULL;
    header = NULL;

    return to_user_size;
}

/* Function to create a packet header given its fields. The user is responsible
 * for allocating space for the header and freeing it. Control parameters ACK,
 * RST, SYN, FIN are treated as booleans */
static void
packet_header(microtcp_header_t *header, uint32_t seq_number,
              uint32_t ack_number, int ack, int rst, int syn,
              int fin, uint16_t window, uint32_t data_len,
              uint32_t future0, uint32_t future1, uint32_t future2,
              uint32_t checksum) {

    header->seq_number = seq_number;
    header->ack_number = ack_number;
    header->window = window;
    header->data_len = data_len;
    header->future_use0 = future0;
    header->future_use1 = future1;
    header->future_use2 = future2;
    header->checksum = checksum;

    header->control = 0;
    if (ack) {
        header->control |= ACK;
    }

    if (rst) {
        header->control |= RST;
    }

    if (syn) {
        header->control |= SYN;
    }

    if (fin) {
        header->control |= FIN;
    }
}

static int check_checksum_header(microtcp_header_t *header) {
    uint32_t tmp_checksum = header->checksum;

    header->checksum = 0;

    return (crc32((const uint8_t *)header, sizeof(*header)) != tmp_checksum);
}

static int check_checksum_packet(uint8_t *packet, uint32_t packet_size, uint32_t correct_checksum) {
    return (crc32(packet, packet_size) == correct_checksum);
}

static void
update_congestion_control(microtcp_sock_t *socket, int timeout, int ack_count, size_t transmission_cwnd) {
    if (timeout) {
        socket->ssthresh = transmission_cwnd / 2;
        socket->cwnd = MICROTCP_MSS;
    } else if (ack_count == 3) {
        socket->ssthresh = transmission_cwnd / 2;
        socket->cwnd = transmission_cwnd / 2 + MICROTCP_MSS;
    } else if (ack_count == 0) {
        if (transmission_cwnd < socket->ssthresh) {
            socket->cwnd += MICROTCP_MSS;
        } else {
            socket->cwnd += MICROTCP_MSS * MICROTCP_MSS / transmission_cwnd;
        }
    }
}

static size_t roundUp(size_t numToRound, size_t multiple) {
    size_t remainder = numToRound % multiple;
    if (remainder == 0)
        return numToRound;

    return numToRound + multiple - remainder;
}
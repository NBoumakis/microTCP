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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define SYN (1 << 14)
#define ACK (1 << 12)

enum State {
    SLOW_START,
    CONGESTION_AVOID
};

enum State slow_start(microtcp_sock_t *socket, int timeout, int duplicate_ack) {
    if (timeout) {
        socket->ssthresh = socket->cwnd / 2;
        socket->cwnd = min(MICROTCP_MSS, socket->ssthresh);

        return SLOW_START;
    }
    /*
      if (duplicate_ack == 3) {
          socket->ssthresh = socket->cwnd/2;
          socket->cwnd = socket->ssthresh + 3*MICROTCP_MSS;

          return CONGESTION_AVOID;
      }
  */
    if (socket->cwnd >= socket->ssthresh) {
        return CONGESTION_AVOID;
    } else {
        socket->cwnd += MICROTCP_MSS;

        return SLOW_START;
    }
}

enum State congest_avoid(microtcp_sock_t *socket, int timeout,
                         int duplicate_ack) {
    if (timeout) {
        socket->ssthresh = socket->cwnd / 2;
        socket->cwnd = min(MICROTCP_MSS, socket->ssthresh);

        return SLOW_START;
    }

    if (duplicate_ack == 3) {
        socket->ssthresh = socket->cwnd / 2;
        socket->cwnd = socket->cwnd / 2 + MICROTCP_MSS;
    } else if (duplicate_ack == 0) {
        socket->cwnd += MICROTCP_MSS * (MICROTCP_MSS / socket->cwnd);
    }

    return CONGESTION_AVOID;
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

    sock.sd = socket(domain, SOCK_DGRAM, IPPROTO_UDP);

    if (sock.sd == -1) {
        sock.state = INVALID;
    }

    sock.cwnd = MICROTCP_MSS;
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
    header.checksum = crc32(&header, sizeof(header));
    if (send(socket->sd, &header, sizeof(header), 0) < 0) {
        printf("Error: 3-way handshake: SYN: Send packet\n");
        return -1;
    }
    ++socket->seq_number;

    /*receive packet SYN-ACK */
    if (recv(socket->sd, &header, sizeof(header), 0) < 0) {
        printf("Error: 3-way handshake: SYN,ACK: Receive packet\n");
        return -1;
    }

    if (header.checksum != crc32(&header, sizeof(header))) {
        printf("Error: 3-way handshake: SYN,ACK: Checksum\n");
        return -1;
    }

    /*elegxos Ack number poy elaba*/
    if ((socket->seq_number + 1) != header.ack_number) {
        printf("Error: 3-way handshake: SYN,ACK: Ack number\n");
        return -1;
    }

    /*elegxos gia ACK=1 kai SYN=1*/
    if (header.control != (SYN | ACK)) {
        printf("Error 3-way handshake: SYN,ACK: Control fields\n");
        return -1;
    }

    socket->curr_win_size = header.window;
    socket->ack_number = header.seq_number + 1;

    /*send ACK sto SYN-ACK*/
    packet_header(&header, socket->seq_number, socket->ack_number, 1, 0, 0, 0, MICROTCP_WIN_SIZE, 0, 0, 0, 0, 0);
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

    if (connect(socket->sd, address, address_len) == -1) {
        return -1;
    }

    /*receive SYN=1, seq=N HEADER*/
    if (recv(socket->sd, &header, MICROTCP_RECVBUF_LEN, 0) == -1)
        return -1;

    if (crc32(&header, sizeof(header)) != header.checksum) {
        printf("Error: 3-way handshake: SYN: Checksum\n");
        return -1;
    }

    if (header.control != SYN) { // check SYN sent from client
        printf("Error: 3-way handshake: SYN: Control field\n");
        return -1;
    }

    socket->ack_number = header.seq_number + 1;

    packet_header(&header, socket->seq_number, socket->ack_number, 1, 0, 1, 0, MICROTCP_WIN_SIZE, 0, 0, 0, 0, 0);
    header.checksum = crc32(&header, sizeof(header));

    /*send SYN=1, ACK=1 from control, seq=M,ack=N+1 HEADER*/
    if (send(socket->sd, &header, sizeof(header), 0) == -1)
        return -1;

    ++socket->seq_number;

    /*receive ACK=1 from control, seq=N+1,ack=M+1 HEADER*/
    if (recv(socket->sd, &header, MICROTCP_RECVBUF_LEN, 0) == -1)
        return -1;

    if (crc32(&header, sizeof(header)) != header.checksum) {
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

    ++socket->ack_number;
    socket->curr_win_size = header.window;

    socket->recvbuf = (uint8_t *)malloc(sizeof(uint8_t) * MICROTCP_RECVBUF_LEN);

    return 0; // return 0 for success
}

int microtcp_shutdown(microtcp_sock_t *socket, int how) {
    microtcp_header_t *header = malloc(sizeof(microtcp_header_t));

    if (socket->state == CLOSING_BY_PEER) {
        // Server side confirmed
        packet_header(header, socket->seq_number, socket->ack_number + 1, 1, 0, 0,
                      0, MICROTCP_WIN_SIZE, 0, 0, 0, 0, 0);

        send(socket->sd, header, sizeof(microtcp_header_t), 0);
        socket->ack_number += 1;

        packet_header(header, socket->seq_number, socket->ack_number, 1, 0, 0, 1,
                      MICROTCP_WIN_SIZE, 0, 0, 0, 0, 0);
        send(socket->sd, header, sizeof(microtcp_header_t), 0);

        recv(socket->sd, header, sizeof(microtcp_header_t), 0);

        if (header->control != (1 << 12) ||
            socket->ack_number != header->seq_number ||
            socket->seq_number + 1 != header->ack_number) {
            free(header);
            return -1;
        }

        socket->state = CLOSED;

        free(socket->recvbuf);

        close(socket->sd); // Syscall
    } else if (socket->state == ESTABLISHED) {
        // Invoked by client
        socket->state = CLOSING_BY_HOST;

        packet_header(header, socket->seq_number, socket->ack_number, 1, 0, 0, 1,
                      MICROTCP_WIN_SIZE, 0, 0, 0, 0, 0);
        send(socket->sd, header, sizeof(microtcp_header_t), 0);

        recv(socket->sd, header, sizeof(microtcp_header_t), 0);

        if (header->control != (1 << 12) ||
            socket->seq_number + 1 != header->ack_number) {
            free(header);
            return -1;
        }

        socket->seq_number += 1;

        recv(socket->sd, header, sizeof(microtcp_header_t), 0);

        if (header->control != ((1 << 12) | (1 << 15))) {
            return -1;
        }

        socket->ack_number = header->seq_number + 1;

        packet_header(header, socket->seq_number, socket->ack_number, 1, 0, 0, 0,
                      MICROTCP_WIN_SIZE, 0, 0, 0, 0, 0);
        send(socket->sd, header, sizeof(microtcp_header_t), 0);

        free(socket->recvbuf);

        close(socket->sd); // Syscall

        socket->state = CLOSED;
    }

    free(header);

    return 0;
}

ssize_t microtcp_send(microtcp_sock_t *socket, const void *buffer,
                      size_t length, int flags) {
    size_t remaining, data_sent, bytes_to_send, chunks_count, i, seq_number,
        chunk_size, max_ack = 0;
    uint8_t *chunk;
    uint8_t duplicate_ack;
    microtcp_header_t header;
    struct timeval timeout = {.tv_sec = 0, .tv_usec = MICROTCP_ACK_TIMEOUT_US};

    enum State (*actions[2])(microtcp_sock_t *, int, int) = {slow_start,
                                                             congest_avoid};
    enum State state = SLOW_START;

    remaining = length;
    while (data_sent < length) {
        bytes_to_send = min(socket->curr_win_size, socket->cwnd, remaining);
        chunks_count = bytes_to_send / MICROTCP_MSS;

        chunk_size = MICROTCP_MSS + sizeof(microtcp_header_t);
        chunk = malloc(chunk_size);

        for (i = 0; i < chunks_count; i++) {
            packet_header(&header, seq_number, socket->ack_number, 0, 0, 0, 0,
                          socket->curr_win_size, MICROTCP_MSS, 0, 0, 0, 0);

            memcpy(chunk, &header, sizeof(microtcp_header_t));
            memcpy(chunk + sizeof(microtcp_header_t),
                   buffer + data_sent + i * MICROTCP_MSS, MICROTCP_MSS);

            header.checksum = crc32(chunk, chunk_size);

            send(socket->sd, chunk, chunk_size, flags);
        }

        free(chunk);

        /* Check if there is a semi - filled chunk */
        if (bytes_to_send % MICROTCP_MSS) {
            chunks_count++;

            chunk_size = (bytes_to_send % MICROTCP_MSS) + sizeof(microtcp_header_t);
            chunk = malloc(chunk_size);

            packet_header(&header, seq_number, socket->ack_number, 0, 0, 0, 0,
                          socket->curr_win_size, bytes_to_send % MICROTCP_MSS, 0, 0,
                          0, 0);

            memcpy(chunk, &header, sizeof(microtcp_header_t));
            memcpy(chunk + sizeof(microtcp_header_t),
                   buffer + data_sent + (chunks_count - 1) * MICROTCP_MSS,
                   bytes_to_send % MICROTCP_MSS);

            header.checksum = crc32(chunk, chunk_size);

            send(socket->sd, chunk, chunk_size, flags);

            free(chunk);
        }

        /* Get the ACKs */
        if (setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                       sizeof(struct timeval)) < 0) {
            perror(" setsockopt ");
        }

        for (i = 0; i < chunks_count; i++) {
            ssize_t rcv_ret = recv(socket->sd, &header, sizeof(microtcp_header_t), 0);

            if (rcv_ret == -1) {
                duplicate_ack = 0;
            } else {
                if (max_ack < header.ack_number) {
                    max_ack = header.ack_number;
                    duplicate_ack = 0;
                } else if (max_ack == header.ack_number) {
                    ++duplicate_ack;
                }
            }

            state = actions[state](socket, rcv_ret == -1, duplicate_ack);
        }

        /* Retransmissions */
        /* Update window */
        /* Update congestion control */
        remaining -= bytes_to_send;
        data_sent += bytes_to_send;
        /* XX */
    }
}

ssize_t microtcp_recv(microtcp_sock_t *socket, void *buffer, size_t length,
                      int flags) {
    /* Your code here */
}

/* Function to create a packet header given its fields. The user is responsible
 * for allocating space for the header and freeing it. Control parameters ACK,
 * RST, SYN, FIN are treated as booleans */
static void packet_header(microtcp_header_t *header, uint32_t seq_number,
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
        header->control |= (1 << 12);
    }

    if (rst) {
        header->control |= (1 << 13);
    }

    if (syn) {
        header->control |= (1 << 14);
    }

    if (fin) {
        header->control |= (1 << 15);
    }
}

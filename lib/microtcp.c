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
#include <netinet/ip.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static void packet_header(microtcp_header_t *header, uint32_t seq_number,
                          uint32_t ack_number, int ACK, int RST, int SYN, int FIN,
                          uint16_t window, uint32_t data_len, uint32_t future_use0,
                          uint32_t future_use1, uint32_t future_use2,
                          uint32_t checksum);

microtcp_sock_t microtcp_socket(int domain, int type, int protocol) {
    microtcp_sock_t sock;
    srand(time(NULL));

    sock.state = UNKNOWN;

    sock.seq_number = random();

    sock.sd = socket(domain, SOCK_DGRAM, IPPROTO_UDP);

    if (sock.sd == -1) {
        sock.state = INVALID;
    }

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

    socket->remote_addr = *address;
    socket->addr_len = address_len;

    socket->state = LISTEN;

    return 0;
}

int microtcp_connect(microtcp_sock_t *socket, const struct sockaddr *address,
                     socklen_t address_len) {
    int SYN = 1 << 14;
    int ACK = 1 << 12;
    int SYNACK = ACK | SYN;

    microtcp_header_t *header =
        (microtcp_header_t *)malloc(sizeof(microtcp_header_t));

    if (socket->state == INVALID)
        return -1;

    if (connect(socket->sd, address, address_len) == -1) {
        return -1;
    }

    /*allocated buffer*/
    socket->recvbuf = (uint8_t *)malloc(sizeof(uint8_t) * MICROTCP_RECVBUF_LEN);

    /*send packet SYN*/
    header->seq_number = socket->seq_number;
    header->ack_number = 0;
    header->window = MICROTCP_WIN_SIZE;
    header->data_len = 0;
    header->future_use0 = 0;
    header->future_use1 = 0;
    header->future_use2 = 0;
    header->checksum = 0;

    sendto(socket->sd, header, sizeof(header), 0, &(socket->remote_addr),
           socket->addr_len);

    /*receive packet SYN-ACK */
    recvfrom(socket->sd, header, sizeof(header), 0, &(socket->remote_addr),
             &(socket->addr_len));

    /*elegxos Ack number poy elaba*/
    if ((socket->seq_number + 1) != header->ack_number) {
        printf("error elegxos ack number\n");
        return -1;
    } else {
        printf("ok,server Ack\n");
    }

    /*elegxos gia ACK=1 kai SYN=1*/
    if (header->control != SYNACK) {
        printf("error elegxos SYNACK\n");
        return -1;
    } else {
        printf("ok,server SYNACK\n");
    }

    /*send ACK sto SYN-ACK*/
    header->seq_number = socket->seq_number + 1;
    header->ack_number = header->seq_number + 1;
    header->control = ACK;
    header->window = MICROTCP_WIN_SIZE;
    header->data_len = 0;
    header->future_use0 = 0;
    header->future_use1 = 0;
    header->future_use2 = 0;
    header->checksum = 0;

    sendto(socket->sd, header, sizeof(header), 0, &(socket->remote_addr),
           socket->addr_len);

    /*o seq_num kai o ack_num mesa sth socket prepei na allajoun*/
    socket->seq_number = socket->seq_number + 1;
    socket->ack_number = header->ack_number;

    socket->state = ESTABLISHED;

    free(header);

    return 0;
}

int microtcp_accept(microtcp_sock_t *socket, struct sockaddr *address,
                    socklen_t address_len) {
    uint16_t SYN = 1 << 14;      // the last-1==1
    uint16_t ACK = 1 << 12;      // the last-3==1
    uint16_t SYNACK = SYN | ACK; // SYN=1, ACK=1

    microtcp_header_t *header =
        (microtcp_header_t *)malloc(sizeof(microtcp_header_t));

    socket->recvbuf = (uint8_t *)malloc(sizeof(uint8_t) * MICROTCP_RECVBUF_LEN);
    // socket->recvbuf([0-3]) refers to seq, [4-7] to ack
    // and [8-9] in control

    if (socket->state == INVALID) {
        printf("Socket invalid!\n");
        return -1;
    }

    /*receive SYN=1, seq=N HEADER*/

    recvfrom(socket->sd, header, sizeof(header), 0, &(socket->remote_addr),
             &(socket->addr_len));

    if (recv(socket, header, MICROTCP_RECVBUF_LEN, 0) == -1)
        return -1;

    if (header->control != SYN) { // check SYN sent from client
        printf("Error with SYN, first packet from client\n!");
        return -1;
    }

    socket->ack_number = header->seq_number + 1;

    // create the header that will sent to client
    header->seq_number = socket->seq_number;
    header->ack_number = socket->ack_number;
    header->control = SYNACK;
    header->window = MICROTCP_RECVBUF_LEN;
    header->data_len = 0;
    header->future_use0 = 0;
    header->future_use1 = 0;
    header->future_use2 = 0;
    header->checksum = 0;

    /*send SYN=1,ACK=1 from control, seq=M,ack=N+1 HEADER*/

    sendto(socket->sd, header, sizeof(header), 0, &(socket->remote_addr),
           socket->addr_len);

    /*receive ACK=1 from control, seq=N+1,ack=M+1 HEADER*/
    recvfrom(socket->sd, header, sizeof(header), 0, &(socket->remote_addr),
             &(socket->addr_len));

    if (send(socket, header, sizeof(header), 0) == -1)
        return -1;

    /*receive ACK=1 from control, seq=N+1,ack=M+1 HEADER*/
    if (recv(socket, header, MICROTCP_RECVBUF_LEN, 0) == -1)
        return -1;

    if (header->control != ACK) { // check ACK from client, second packet recv
        printf("Error with ACK,second packet receive from server!\n");
        return -1;
    }

    if (header->seq_number !=
        socket->ack_number) { // N+1 from header equals seq+1 that server sent
        printf("Error with seq (N+1) sent!\n");
        return -1;
    }

    if (header->ack_number !=
        socket->seq_number + 1) { // M+1 from header equals ack that server sent
        printf("Error with seq (M+1) sent!\n");
        return -1;
    }

    free(header);

    return 0; // return 0 for success
}

int microtcp_shutdown(microtcp_sock_t *socket, int how) {
    microtcp_header_t *header = malloc(sizeof(microtcp_header_t));

    if (socket->state == CLOSING_BY_PEER) {
        // Server side confirmed
        packet_header(header, socket->seq_number, socket->ack_number + 1, 1, 0, 0, 0,
                      MICROTCP_WIN_SIZE, 0, 0, 0, 0, 0);

        sendto(socket->sd, header, sizeof(microtcp_header_t), 0,
               &(socket->remote_addr), socket->addr_len);
        socket->ack_number += 1;

        packet_header(header, socket->seq_number, socket->ack_number, 1, 0, 0, 1,
                      MICROTCP_WIN_SIZE, 0, 0, 0, 0, 0);
        sendto(socket->sd, header, sizeof(microtcp_header_t), 0,
               &(socket->remote_addr), socket->addr_len);

        recvfrom(socket->sd, header, sizeof(microtcp_header_t), 0,
                 &(socket->remote_addr), &(socket->addr_len));

        if (header->control != (1 << 12) ||
            socket->ack_number != header->seq_number ||
            socket->seq_number + 1 != header->ack_number) {
            free(header);
            return -1;
        }

        socket->state = CLOSED;
    } else if (socket->state == ESTABLISHED) {
        // Invoked by client
        packet_header(header, socket->seq_number, socket->ack_number, 1, 0, 0, 1,
                      MICROTCP_WIN_SIZE, 0, 0, 0, 0, 0);
        sendto(socket->sd, header, sizeof(microtcp_header_t), 0,
               &(socket->remote_addr), socket->addr_len);

        recvfrom(socket->sd, header, sizeof(microtcp_header_t), 0,
                 &(socket->remote_addr), &(socket->addr_len));

        if (header->control != (1 << 12) ||
            socket->seq_number + 1 != header->ack_number) {
            free(header);
            return -1;
        }

        socket->seq_number += 1;

        recvfrom(socket->sd, header, sizeof(microtcp_header_t), 0,
                 &(socket->remote_addr), &(socket->addr_len));

        if (header->control != ((1 << 12) | (1 << 15))) {
            return -1;
        }

        socket->ack_number = header->seq_number + 1;

        packet_header(header, socket->seq_number, socket->ack_number, 1, 0, 0, 0,
                      MICROTCP_WIN_SIZE, 0, 0, 0, 0, 0);
        sendto(socket->sd, header, sizeof(microtcp_header_t), 0,
               &(socket->remote_addr), socket->addr_len);

        socket->state = CLOSED;
    }

    free(header);
    free(socket->recvbuf);

    return 0;
    close(socket->sd); // Syscall
}

ssize_t microtcp_send(microtcp_sock_t *socket, const void *buffer, size_t length,
                      int flags) {
    /* Your code here */
}

ssize_t microtcp_recv(microtcp_sock_t *socket, void *buffer, size_t length,
                      int flags) {
    /* Your code here */
}

/* Function to create a packet header given its fields. The user is responsible for
 * allocating space for the header and freeing it. Control parameters ACK, RST,
 * SYN, FIN are treated as booleans */
static void packet_header(microtcp_header_t *header, uint32_t seq_number,
                          uint32_t ack_number, int ACK, int RST, int SYN, int FIN,
                          uint16_t window, uint32_t data_len, uint32_t future0,
                          uint32_t future1, uint32_t future2, uint32_t checksum) {

    header->seq_number = seq_number;
    header->ack_number = ack_number;
    header->window = window;
    header->data_len = data_len;
    header->future_use0 = future0;
    header->future_use1 = future1;
    header->future_use2 = future2;
    header->checksum = checksum;

    header->control = 0;
    if (ACK) {
        header->control |= (1 << 12);
    }

    if (RST) {
        header->control |= (1 << 13);
    }

    if (SYN) {
        header->control |= (1 << 14);
    }

    if (FIN) {
        header->control |= (1 << 15);
    }
}

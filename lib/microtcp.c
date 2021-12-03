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
    /* call bind(socket->sd, ...)
     * call listen?
     * socket->state = LISTEN
     * retun 0 unless !bind || socket_invalid */
}

int microtcp_connect(microtcp_sock_t *socket, const struct sockaddr *address,
                     socklen_t address_len) {
    /**
     *
     * State checking
     * Malloc header, assign seq
     * send(header)
     * recv(buffer)
     * header->seq += 1
     * header->ack = buffer->seq+1
     * send(header)
     *
     * setting values state= ESTABLISHED
     *
     * return
     */
}

int microtcp_accept(microtcp_sock_t *socket, struct sockaddr *address,
                    socklen_t address_len) {
    /**
     * call accept(socket->sd, ...)
     * receive
     * socket->ack = buffer->seq+1
     * socket->seq = random()
     * send(header)
     * receive
     * check
     * socket->state = ESTABLISHED
     * return 0 unless !bind || socket_invalid */
}

int microtcp_shutdown(microtcp_sock_t *socket, int how) {
    if (socket->state == CLOSING_BY_PEER) {
        // Server side confirmed
        /*send ACK
        send FIN
        recv ACK
        error_checking*/
        socket->state = CLOSED;
    } else if (socket->state == ESTABLISHED) {
        // Invoked by client
        /*send FIN
        recv ACK
        recv FIN
        send ACK*/
        socket->state = CLOSED;
    }

    // shutdown(); // Syscall
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

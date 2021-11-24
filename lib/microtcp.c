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

microtcp_sock_t x;

microtcp_sock_t microtcp_socket(int domain, int type, int protocol) {
    /*x.state=UKNOWN; Invalid of failure*/

    /*find a number seq_num*/

    /*call system x.sd=socket()*/

    /*rest of fields =0*/

    socket_t.sd=socket(domain,type,protocol);
    socket_t.seq_number=10;
    socket_t.state=UNKNOWN;
    return socket_t;
}

int microtcp_bind(microtcp_sock_t *socket, const struct sockaddr *address,
                  socklen_t address_len) {
    if(socket->state==INVALID)   
        return -1;

    
    if(bind(socket->sd,address,address_len) < 0){
        return -1;
    }

    socket->state=LISTEN;

    return 0;
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
    uint16_t SYN=1<<13;
    uint16_t ACK=1<<11;
    uint16_t SYNACK=SYN | ACK; //SYN=1, ACK=1
    uint8_t client_seq[4];
    uint8_t client_ack[4];
    uint8_t client_control[2];
    microtcp_header_t *header=( microtcp_header_t * )malloc(sizeof ( microtcp_header_t ) );

    socket->recvbuf=(uint8_t*)malloc(sizeof(uint8_t)*MICROTCP_RECVBUF_LEN);
    

    if(accept(socket->sd,address,address_len) == -1){
        printf("Error ,accept()\n");
        return -1;
    }

    /*receive*/
    microtcp_recv(socket, socket->recvbuf, MICROTCP_RECVBUF_LEN,0);
    client_seq[0]=socket->recvbuf[0]; //seq=N from client
    client_seq[1]=socket->recvbuf[1];
    client_seq[2]=socket->recvbuf[2];
    client_seq[3]=socket->recvbuf[3];

    client_control[0]=socket->recvbuf[8]; //SYN from client
    client_control[1]=socket->recvbuf[9];

    if (*(uint16_t *)client_control != SYN){
        printf("Error with SYN, first packet from client!");
        return 0;
    }

    //create the header that will sent to client
    header->seq_number=socket->seq_number;
    header->ack_number=(*(uint32_t*)client_seq)+1;
    header->control=SYNACK;
    header->window=MICROTCP_RECVBUF_LEN;
    header->data_len=1;
    header->future_use0=0;
    header->future_use1=0;
    header->future_use2=0;
    header->checksum=0;

    microtcp_send(socket,header,sizeof(header),0); //send packet

    microtcp_recv(socket, socket->recvbuf, MICROTCP_RECVBUF_LEN,0);
    client_seq[0]=socket->recvbuf[0]; //seq=N from client
    client_seq[1]=socket->recvbuf[1];
    client_seq[2]=socket->recvbuf[2];
    client_seq[3]=socket->recvbuf[3];

    client_ack[0]=socket->recvbuf[4];
    client_ack[1]=socket->recvbuf[5];
    client_ack[2]=socket->recvbuf[6];
    client_ack[3]=socket->recvbuf[7];

    client_control[0]=socket->recvbuf[8]; //SYN from client
    client_control[1]=socket->recvbuf[9];

    if (*(uint16_t *)client_ack != ACK){
        printf("Error with ACK,second packet receive from server!");
    }

    if ((header->seq_number+1) != *(uint32_t*)client_ack){
        printf("Error with ack sent!");
        return 0;
    }
    if (header->ack_number != *(uint32_t*)client_seq){
        printf("Error with seq sent!");
        return 0;
    }
}

int microtcp_shutdown(microtcp_sock_t *socket, int how) {
    /**
     * if (state==BY_PEER) {
     *    // Server side confirmed
     *    send ACK
     *    send FIN
     *    recv ACK
     *    error_checking
     *    state = CLOSED
     * } else if (state == ESTABLISHED) {
     *    // Invoked by client
     *    send FIN
     *    recv ACK
     *    recv FIN
     *    send ACK
     *    state = CLOSED
     * }
     *
     * shutdown() // Syscall
     */
}

ssize_t microtcp_send(microtcp_sock_t *socket, const void *buffer, size_t length,
                      int flags) {
    /* Your code here */
}

ssize_t microtcp_recv(microtcp_sock_t *socket, void *buffer, size_t length,
                      int flags) {
    /* Your code here */
}

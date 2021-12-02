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
    int SYN=1<<14;
    int ACK=1<<12;
    int SYNACK=ACK | SYN;
  
    uint8_t seq_server[4];
    uint8_t ack_server[4];
    uint8_t control[2];
    
   
    microtcp_header_t *header=( microtcp_header_t * )malloc(sizeof ( microtcp_header_t ) );


    if(socket->state == INVALID)
        return -1;

    if(connect(socket->sd,address,address_len)==-1){
        return -1;
    }

    /*allocated buffer*/
    socket->recvbuf=(uint8_t*)malloc(sizeof(uint8_t)*MICROTCP_RECVBUF_LEN);
    
    /*send packet SYN*/
    header->seq_number=socket->seq_number;
    header->ack_number=0;
    header->window=MICROTCP_WIN_SIZE;
    header->data_len=1;
    header->future_use0=0;
    header->future_use1=0;
    header->future_use2=0;
    header->checksum=0;
    

    socket->seq_number=socket->seq_number+header->data_len;

    microtcp_send(socket, header ,sizeof(header),0);

    /*receive packet SYN-ACK */
    microtcp_recv(socket, socket->recvbuf, MICROTCP_RECVBUF_LEN,0);
   

    /*ACK=SYN=1*/
  


    seq_server[0]=socket->recvbuf[0];
    seq_server[1]=socket->recvbuf[1];
    seq_server[2]=socket->recvbuf[2];
    seq_server[3]=socket->recvbuf[3];

    ack_server[0]=socket->recvbuf[4];
    ack_server[1]=socket->recvbuf[5];
    ack_server[2]=socket->recvbuf[6];
    ack_server[3]=socket->recvbuf[7];

    control[0]=socket->recvbuf[8];
    control[1]=socket->recvbuf[9];
  
    /*elegxos Ack number*/
    /*to exw balei to +1 ,line=108*/
   
    if( socket->seq_number != (*(uint32_t*)ack_server) ){
        printf("line:150,error elegxos ack number\n");
        return -1;
    }
    else{
        printf("ok,server Ack=%d\n",*(uint32_t*)ack_server);
    }

    

    /*elegxos gia ACK=1 kai SYN=1*/
   
    if( *(uint16_t*)control != SYNACK){
        printf("line:162 ,error elegxos SYNACK\n");
        return -1;
    }
    else{
        printf("ok,server SynAck\n");
    }

    /*send ACK sto SYN-ACK*/
   
    header->seq_number=socket->seq_number;

    header->ack_number=*(uint32_t  *)(seq_server);
    header->ack_number=header->ack_number+1;

    header->control=ACK;
    header->window=MICROTCP_WIN_SIZE;
    header->data_len=1;
    header->future_use0=0;
    header->future_use1=0;
    header->future_use2=0;
    header->checksum=0;

 

    

    socket->seq_number=socket->seq_number+header->data_len;


    microtcp_send(socket, header ,sizeof(header),0);



    socket->state=ESTABLISHED;

    return 0;

}

int microtcp_accept(microtcp_sock_t *socket, struct sockaddr *address,
                    socklen_t address_len) {
    uint16_t SYN=1<<14;
    uint16_t ACK=1<<12;
    uint16_t SYNACK=SYN | ACK; //SYN=1, ACK=1
    uint8_t client_seq[4];
    uint8_t client_ack[4];
    uint8_t client_control[2];
    uint32_t server_seq,server_ack;
    microtcp_header_t *header=( microtcp_header_t * )malloc(sizeof ( microtcp_header_t ) );

    socket->recvbuf=(uint8_t*)malloc(sizeof(uint8_t)*MICROTCP_RECVBUF_LEN);
    

    if(accept(socket->sd,address,address_len) == -1){
        printf("Error ,accept()\n");
        return -1;
    }

    /*receive SYN=1, seq=N HEADER*/
    if (microtcp_recv(socket, socket->recvbuf, MICROTCP_RECVBUF_LEN,0) == -1) return -1;
    
    
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
    header->data_len=0;
    header->future_use0=0;
    header->future_use1=0;
    header->future_use2=0;
    header->checksum=0;

    server_seq=header->seq_number;
    server_ack=header->ack_number;
    printf("seq_server=%d\n",header->seq_number );
    printf("ack_server=%d\n",header->ack_number);

    /*send SYN=1,ACK=1 from control, seq=M,ack=N+1 HEADER*/
    if (microtcp_send(socket,header,sizeof(header),0) == -1) return -1;

    /*receive ACK=1 from control, seq=N+1,ack=M+1 HEADER*/
    if (microtcp_recv(socket, socket->recvbuf, MICROTCP_RECVBUF_LEN,0) == -1) return -1;

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

    if (*(uint16_t *)client_control != ACK){ 
        printf("Error with ACK,second packet receive from server!\n");
        return -1;
    }
   
    if(*(uint32_t*)client_ack != (header->seq_number+1)){
        printf("Error received ack\n");
    }

    return 0;
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

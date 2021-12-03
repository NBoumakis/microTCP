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
    header->data_len=0;
    header->future_use0=0;
    header->future_use1=0;
    header->future_use2=0;
    header->checksum=0;
    

    send(socket, header ,sizeof(header),0);


    /*receive packet SYN-ACK */
    recv(socket, header, MICROTCP_RECVBUF_LEN,0);
   

  
    /*elegxos Ack number poy elaba*/
  
    if( socket->seq_number+1 != header->ack_number) ){
        printf("error elegxos ack number\n");
        return -1;
    }
    else{
        printf("ok,server Ack\n");
    }

    

    /*elegxos gia ACK=1 kai SYN=1*/
   
    if( header->control != SYNACK){
        printf("error elegxos SYNACK\n");
        return -1;
    }
    else{
        printf("ok,server SYNACK\n");
    }

    /*send ACK sto SYN-ACK*/
   
    header->seq_number=socket->seq_number+1;
    header->ack_number=header->seq_number+1;
    header->control=ACK;
    header->window=MICROTCP_WIN_SIZE;
    header->data_len=0;
    header->future_use0=0;
    header->future_use1=0;
    header->future_use2=0;
    header->checksum=0;

 

    send(socket, header ,sizeof(header),0);

    /*o seq_num kai o ack_num mesa sth socket prepei na allajoun*/
    socket->seq_number=socket->seq_number+1;
    socket->ack_number=header->ack_number;

    socket->state=ESTABLISHED;

    free(header);

    return 0;

}

int microtcp_accept(microtcp_sock_t *socket, struct sockaddr *address,
                    socklen_t address_len) {
    uint16_t SYN=1<<14; //the last-1==1
    uint16_t ACK=1<<12; //the last-3==1
    uint16_t SYNACK=SYN | ACK; //SYN=1, ACK=1
    

    microtcp_header_t *header=( microtcp_header_t * )malloc(sizeof ( microtcp_header_t ) );

    socket->recvbuf=(uint8_t*)malloc(sizeof(uint8_t)*MICROTCP_RECVBUF_LEN);
    //socket->recvbuf([0-3]) refers to seq, [4-7] to ack
    //and [8-9] in control

    
    if(socket->state == INVALID){
        printf("Socket invalid!\n");
        return -1;
    }

    /*receive SYN=1, seq=N HEADER*/
    if (recv(socket, header, MICROTCP_RECVBUF_LEN,0) == -1) return -1;

    
    if (header->control != SYN){ //check SYN sent from client
        printf("Error with SYN, first packet from client\n!");
        return -1;
    }
    
    socket->ack_number=header->seq_number +1;

    //create the header that will sent to client
    header->seq_number=socket->seq_number;
    header->ack_number=socket->ack_number;
    header->control=SYNACK;
    header->window=MICROTCP_RECVBUF_LEN;
    header->data_len=0;
    header->future_use0=0;
    header->future_use1=0;
    header->future_use2=0;
    header->checksum=0;

    
    /*send SYN=1,ACK=1 from control, seq=M,ack=N+1 HEADER*/
    if (send(socket,header,sizeof(header),0) == -1) return -1;

    
    /*receive ACK=1 from control, seq=N+1,ack=M+1 HEADER*/
    if (recv(socket, header, MICROTCP_RECVBUF_LEN,0) == -1) return -1;
 
    
    if (header->control != ACK){ //check ACK from client, second packet recv
        printf("Error with ACK,second packet receive from server!\n");
        return -1;
    }

    
    if (header->seq_number != socket->ack_number){ //N+1 from header equals seq+1 that server sent
        printf("Error with seq (N+1) sent!\n");
        return -1;
    }
    
    if (header->ack_number != socket->seq_number+1){ //M+1 from header equals ack that server sent
        printf("Error with seq (M+1) sent!\n");
        return -1;
    }

    free(header);

    return 0; //return 0 for success

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

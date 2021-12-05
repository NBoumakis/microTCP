#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "microtcp.h"


ssize_t microtcp_send(microtcp_sock_t *socket, const void *buffer, size_t length,int flags){

    ssize_t x=5;

    return x;

}

ssize_t microtcp_recv(microtcp_sock_t *socket, void *buffer, size_t length,
                      int flags) {
    ssize_t x=5;

    return x;

}




microtcp_sock_t microtcp_socket(int domain, int type, int protocol) {
    microtcp_sock_t socket_t;
    /*x.state=UKNOWN; Invalid of failure*/

    /*find a number seq_num*/

    /*call system x.sd=socket()*/

    socket_t.sd=socket(domain, SOCK_DGRAM, IPPROTO_UDP);
    socket_t.seq_number=10;
    socket_t.state=UNKNOWN;
    return socket_t;

    /*rest of fields =0*/
}

/*On success, zero is returned.  On error, -1 is returned*/
int microtcp_bind(microtcp_sock_t *socket, const struct sockaddr *address,socklen_t address_len){


    if(socket->state==INVALID)   
        return -1;

    
    if(bind(socket->sd,address,address_len) < 0){
        return -1;
    }

    socket->state=LISTEN;

    return 0;
     
}
/*On success, zero is returned.  On error, -1 is returned*/
int microtcp_connect(microtcp_sock_t *socket, const struct sockaddr *address,socklen_t address_len) {
    
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
    /*seq_num server =20 ack server = 11*/
    socket->recvbuf[0]=20; /*ls byte*/
    socket->recvbuf[1]=0;
    socket->recvbuf[2]=0;
    socket->recvbuf[3]=0;

    socket->recvbuf[4]=11;
    socket->recvbuf[5]=0;
    socket->recvbuf[6]=0;
    socket->recvbuf[7]=0;

    socket->recvbuf[8]=0;
    socket->recvbuf[9]=80;

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
  
    /*TODELETE*/
    printf("socket=%d\n",socket->seq_number);
    printf("ack server=%d\n",*(uint32_t*)ack_server);
    printf("control=%d\n",*(uint16_t*)control);
 

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

    /*TODELETE*/
    printf("seq num=%d\n",header->seq_number); /*11*/
    printf("ack num=%d\n",header->ack_number); /*21*/

    

    socket->seq_number=socket->seq_number+header->data_len;


    microtcp_send(socket, header ,sizeof(header),0);



    socket->state=ESTABLISHED;

    return 0;


}

int main(){
    struct sockaddr_in address;
    microtcp_sock_t my_socket;
    int val,val_connect;

    my_socket=microtcp_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
 
  
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons( 8080 );

    val=microtcp_bind(&my_socket,(struct sockaddr *)&address,sizeof(address));
    printf("val=%d\n",val);
   printf("state=%d\n",my_socket.state);
   val_connect=microtcp_connect(&my_socket,(struct sockaddr *)&address,sizeof(address));
   printf("val_connect=%d\n",val_connect);

    return 0;
}
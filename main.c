#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <inttypes.h>
#include "lib/microtcp.h"
#include "lib/microtcp.c"

int main(void){
    struct sockaddr_in address;
    microtcp_sock_t my_socket;
    int val,val_accept;

    my_socket=microtcp_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080);

    val=microtcp_bind(&my_socket,(struct sockaddr *)&address,sizeof(address));
    printf("val=%d\n",val);
    printf("state=%d\n",my_socket.state);
    val_accept=microtcp_accept(&my_socket,(struct sockaddr *)&address,sizeof(address));
    printf("val_accept=%d\n",val_accept);
    return 0;
}

/*
  microtcp, a lightweight implementation of TCP for teaching,
  and academic purposes.
 
  Copyright (C) 2015-2017  Manolis Surligas <surligas@gmail.com>
 
  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
 
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
 
  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "microtcp.h"
#include "../utils/crc32.h"

microtcp_sock_t socket;

microtcp_sock_t microtcp_socket(int domain, int type, int protocol) {
    /*x.state=UKNOWN; Invalid of failure*/

    /*find a number seq_num*/

    /*call system x.sd=socket()*/

    /*rest of fields =0*/
}

int microtcp_bind(microtcp_sock_t *socket, const struct sockaddr *address,
                  socklen_t address_len) {
    /*call bind(socket->sd, ...)*/
    bind(socket.sd,address,address_len);

     
     /* socket->state = LISTEN*/
     /*retun 0 unless !bind || socket_invalid */
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


#include<netlink/fib_lookup/lookup.h>
#include<netlink/socket.h>
#include<assert.h>
// https://github.com/iproute2/iproute2/blob/main/ip/iproute.c#L1137
int main() {
    struct nl_sock* sock = nl_socket_alloc();
    assert(sock != NULL);
    
}
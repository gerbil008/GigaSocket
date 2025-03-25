#include "gigasocket.hpp"

GigaSocketTLS socket1(6969, 10, "server.key", "server.crt", [](SSL* ssl, int cumfd, std::string message){
    log("got message: "+message);
    socket1.send_msg(ssl, message, 't');
}, [](int cumfd){
    log("Closed socket");
});

GigaSocket socket2(6968, 10, [](int cumfd, std::string message){
    log("got message: "+message);
    socket2.send_msg(cumfd, message, 't');
}, [](int cumfd){
    log("Closed socket");
});

int main() {
    for(;;){
        ;
    }
    return 0;
}
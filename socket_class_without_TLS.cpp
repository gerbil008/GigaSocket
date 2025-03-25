#include <functional>
#include <iostream>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <regex>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string_ops.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#define MAX_BUF_SIZE 2048

int log(std::string msg) {
    std::cout << msg << std::endl;
    return 0;
}

std::string trim_ex(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\n\r");
    if (start == std::string::npos)
        return "";
    size_t end = str.find_last_not_of(" \t\n\r");
    return str.substr(start, end - start + 1);
}

class GigaSocket {
  private:
    int sockfd, connfd, port, len, max_conns;
    struct sockaddr_in servaddr, cli;

    std::string base64_encode(const unsigned char* input, int length) {
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* bio = BIO_new(BIO_s_mem());
        b64 = BIO_push(b64, bio);
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        BIO_write(b64, input, length);
        BIO_flush(b64);

        BUF_MEM* bufferPtr;
        BIO_get_mem_ptr(b64, &bufferPtr);
        std::string result(bufferPtr->data, bufferPtr->length);

        BIO_free_all(b64);
        return result;
    }

    std::string compute_websocket_accept(const std::string& client_key) {
        std::string magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        std::string concatenated = client_key + magic_string;

        unsigned char hash[SHA_DIGEST_LENGTH];
        SHA1(reinterpret_cast<const unsigned char*>(concatenated.c_str()), concatenated.size(), hash);

        return base64_encode(hash, SHA_DIGEST_LENGTH);
    }

    std::string extract_key(std::string request) {
        /*
        GET /chat HTTP/1.1
        Host: example.com
        Upgrade: websocket
        Connection: Upgrade
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
        Sec-WebSocket-Version: 13*/
        std::vector<std::string> splitted = split_str(request, ':');
        std::string tookey = splitted[4];
        std::vector<std::string> next = split_str(tookey, 'S');
        log("extracted key: " + trim_ex(next[0]));
        return trim_ex(next[0]);
    }

    std::string extractKey(const std::string& request) {
        std::regex key_regex("Sec-WebSocket-Key:\\s*(\\S+)");
        std::smatch matches;

        if (std::regex_search(request, matches, key_regex) && matches.size() > 1) {
            return matches[1].str();
        } else {
            return "";
        }
    }

    int handshake(int cumfd) {
        /*
        HTTP/1.1 101 Switching Protocols
        Upgrade: websocket
        Connection: Upgrade
        Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
        */
        char buff[512];
        bzero(buff, 512);
        read(cumfd, buff, sizeof(buff));

        std::string client_key = extractKey(buff);

        std::string gen_key = compute_websocket_accept(client_key);

        std::string response = "HTTP/1.1 101 Switching Protocols\r\n"
                               "Upgrade: websocket\r\n"
                               "Connection: Upgrade\r\n"
                               "Sec-WebSocket-Accept: " +
                               gen_key + "\r\n\r\n";

        ssize_t sent = write(cumfd, response.c_str(), response.size());
        // log("send back: "+response);
        log("id" + std::to_string(cumfd) + "performerd handshake");
        while (true) {
            std::string msg = read_msg(connfd);
            onmessage(cumfd, msg);
        }
        return 0;
    }

    void listener() {
        for (;;) {
            log("entered loop");
            listen(sockfd, max_conns);
            log("after listen");
            len = sizeof(cli);
            unsigned int* len1 = reinterpret_cast<unsigned int*>(&len);
            connfd = accept(sockfd, (struct sockaddr*)&cli, len1);
            std::thread t(std::bind(&GigaSocket::handshake, this, connfd));
            t.detach();
            log("detached");
        }
    }

  public:
    void onmessage(int cumfd, std::string message);
    void onclose(int cumfd);

    GigaSocket(int port, int max_conns) : port(port), max_conns(max_conns) {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        bzero(&servaddr, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        servaddr.sin_port = htons(port);
        bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr));
        std::thread mt(std::bind(&GigaSocket::listener, this));
        mt.detach();
    }

    int close_socket() { return (close(sockfd)); }

    std::string read_msg(int cumfd) {
        unsigned char header[2];
        read(cumfd, header, 2);

        bool masked = header[1] & 0x80;
        uint64_t payload_len = header[1] & 0x7F;

        if (payload_len == 126) {
            unsigned char extended[2];
            read(cumfd, extended, 2);
            payload_len = (extended[0] << 8) | extended[1];
        } else if (payload_len == 127) {
            unsigned char extended[8];
            read(cumfd, extended, 8);
            payload_len = 0;
            for (int i = 0; i < 8; i++) {
                payload_len = (payload_len << 8) | extended[i];
            }
        }

        unsigned char mask[4] = {0};
        if (masked) {
            read(cumfd, mask, 4);
        }

        std::vector<unsigned char> payload(payload_len);
        read(cumfd, payload.data(), payload_len);

        if (masked) {
            for (size_t i = 0; i < payload_len; i++) {
                payload[i] ^= mask[i % 4];
            }
        }

        return std::string(payload.begin(), payload.end());
    }

    void send_msg(int cumfd, const std::string& message, const char indic) {
        std::vector<unsigned char> frame;
        if (indic == 'b') {
            frame.push_back(0x82); // binary
        } else if (indic == 't') {
            frame.push_back(0x81); // text
        }

        if (message.size() < 126) {
            frame.push_back(message.size());
        } else if (message.size() <= 65535) {
            frame.push_back(126);
            frame.push_back((message.size() >> 8) & 0xFF);
            frame.push_back(message.size() & 0xFF);
        } else {
            frame.push_back(127);
            for (int i = 7; i >= 0; i--) {
                frame.push_back((message.size() >> (i * 8)) & 0xFF);
            }
        }

        frame.insert(frame.end(), message.begin(), message.end());
        write(cumfd, frame.data(), frame.size());
    }
};

GigaSocket socket1(6969, 5);

void GigaSocket::onmessage(int cumfd, std::string message) {
    log("Got message: " + message);
    socket1.send_msg(cumfd, message, 't');
}

void GigaSocket::onclose(int cumfd) {
    log("Closed websocket");
}

int main() {
    for (;;) {
        ;
    }
    return 0;
}

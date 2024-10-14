#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>

#include "logger.h"

void initialize_ssl()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        std::cerr << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void listen_for_responses(quill::Logger *logger, SSL *ssl, bool &run, std::mutex &mtx, std::condition_variable &cv)
{
    while (run)
    {
        char buf[1024] = {0};
        int bytes = SSL_read(ssl, buf, sizeof(buf));

        std::lock_guard<std::mutex> lock(mtx);
        if (bytes > 0)
        {
            LOG_INFO(logger, "Server responded: {}", buf);
        }
        else if (bytes == 0)
        {

            LOG_INFO(logger, "Connection closed by the server.", buf);
            run = false;
        }
        else
        {
            LOG_ERROR(logger, "SSL read error or connection lost.");
            run = false;
        }
        cv.notify_one(); // Notify main thread in case of any response or errors
    }
}

int main()
{
    initialize_ssl();
    SSL_CTX *ctx = create_context();

    quill::Logger *logger = initialize_logger();

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8085);
    inet_pton(AF_INET, "192.168.2.2", &addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        perror("Connection error");
        exit(EXIT_FAILURE);
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) == -1)
    {
        ERR_print_errors_fp(stderr);
    }
    else
    {

        LOG_INFO(logger, "Connected with {} encryption.", SSL_get_cipher(ssl));

        bool run = true;
        std::mutex mtx;
        std::condition_variable cv;
        std::thread response_thread(listen_for_responses, logger, ssl, std::ref(run), std::ref(mtx), std::ref(cv));

            const char *msg = "Hello, server!";
            SSL_write(ssl, msg, strlen(msg));

            LOG_DEBUG(logger, "Message sent: {}", msg);

            // Wait for a response or a timeout
            std::unique_lock<std::mutex> lock(mtx);
            if (cv.wait_for(lock, std::chrono::seconds(5)) == std::cv_status::timeout)
            {
                LOG_ERROR(logger, "Timeout waiting for server response.", msg);
            }


        run = false;
        response_thread.join(); // Ensure thread finishes before exit
    }

    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    return 0;
}
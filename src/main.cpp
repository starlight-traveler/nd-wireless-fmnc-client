#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include <iostream>
#include "version.h"
#include "logger.h"

// HTTP

httplib::Client cli("https://0.0.0.0:8085");

// HTTPS
// httplib::Client cli("https://cpp-httplib-server.yhirose.repl.co");


int main() {

    quill::Logger *logger = initialize_logger();

    LOG_DEBUG(logger, "Build date: {}", BUILD_DATE);
    LOG_DEBUG(logger, "Project version: {}", PROJECT_VERSION);
    
    cli.enable_server_certificate_verification(false);

    auto res = cli.Get("/hi");

    LOG_INFO(logger, "Body: {}", res->body);
    LOG_INFO(logger, "Status: {}", res->status);

    return 0; 
}
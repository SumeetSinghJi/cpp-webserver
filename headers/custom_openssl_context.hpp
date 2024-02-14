/*
    Author: Sumeet Singh
    Dated: 12/02/2024
    Minimum C++ Standard: C++11
    Purpose: Declaration/Definition file (combined to segregate third party library code)
    License: MIT License
    Description: read the attached README.md file
*/

#pragma once

#include <iostream>
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>

class custom_openssl {
private:
    SSL_CTX *ssl_ctx;

    // Other members...

public:
    // Constructor and other member functions...

    bool initialise_ssl_context(const std::string &certFile, const std::string &keyFile) {
        // Initialize OpenSSL
        SSL_library_init();
        SSL_load_error_strings();
        OPENSSL_init_ssl(0, NULL);

        // Create an SSL context
        ssl_ctx = SSL_CTX_new(SSLv23_server_method());
        if (!ssl_ctx) {
            // Handle error
            return false;
        }

        // Load certificate and private key
        if (SSL_CTX_use_certificate_file(ssl_ctx, certFile.c_str(), SSL_FILETYPE_PEM) <= 0) {
            // Handle error
            return false;
        }
        if (SSL_CTX_use_PrivateKey_file(ssl_ctx, keyFile.c_str(), SSL_FILETYPE_PEM) <= 0) {
            // Handle error
            return false;
        }

        // Verify private key
        if (!SSL_CTX_check_private_key(ssl_ctx)) {
            // Handle error
            return false;
        }

        // Optionally, configure additional SSL options
        // For example:
        // SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

        std::cout << "SSL webserver .cer and .key pair loaded successfully" << std::endl;

        return true;
    }

    // Other member functions...
};

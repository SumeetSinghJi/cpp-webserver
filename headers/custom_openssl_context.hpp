#include <iostream>
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>

/*
    Author: Sumeet Singh
    Dated: 12/02/2024
    File: Declaration file
    Minimum C++ Standard: C++11
*/

class custom_openssl_context {
private:
    SSL_CTX *ssl_ctx;

    // Other members...

public:
    // Constructor and other member functions...

    bool initialise_ssl_context(const std::string &certFile, const std::string &keyFile) {
        // Initialize OpenSSL
        SSL_library_init();
        SSL_load_error_strings();
        ERR_load_BIO_strings();
        OpenSSL_add_all_algorithms();

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

        std::cout << "SSL webserver .cer and .key pair loaded successfuly" << std::cout;

        return true;
    }

    // Other member functions...
};

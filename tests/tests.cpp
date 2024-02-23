/*
    Author: Sumeet Singh
    Dated: 22/02/2024
    Minimum C++ Standard: C++11
    Purpose: Test lightweight_cpp_webserver.cpp file
    License: MIT License
    Description: Read README.md for more details
*/

#include <gtest/gtest.h>
#include "../headers/lightweight_cpp_webserver.hpp"

class WebServerTest: public ::testing::Test {
    protected:

        // SetUp is a Google Test function
        void SetUp() override {
            // server = new lightweight_cpp_webserver("127.0.0.1", 8080);
        }

        // TearDown is a Google Test function
        void TearDown() override {
            // delete server;
            // lightweight_cpp_webserver::server.ssl_shutdown();
        }

        // lightweight_cpp_webserver* server;

};

/* Test function to determine if Google Test is working, uncomment code related to 
main program in this file and uncomment and run this.
TEST_F(WebServerTest, sandbox_addition_test) {
    int a = 1;
    int b = 2;
    EXPECT_EQ(a + b, 3);
}
*/

/*
TEST_F(WebServerTest, IsValidIPAddressTest) {
    EXPECT_TRUE(server->isValidIPAddress("192.168.1.1"));
    EXPECT_FALSE(server->isValidIPAddress("300.300.300.300"));
    EXPECT_FALSE(server->isValidIPAddress("8.8.8.8"));
}

TEST_F(WebServerTest, IsValidPortAddressTest) {
    int validPort = 8080;
    int invalidPort1 = 1;
    int invalidPort2 = 9000;

    EXPECT_TRUE(server->isValidPortAddress(validPort));
    EXPECT_FALSE(server->isValidPortAddress(invalidPort1));
    EXPECT_FALSE(server->isValidPortAddress(invalidPort2));
}
*/

int main(int argc, char* argv[]) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
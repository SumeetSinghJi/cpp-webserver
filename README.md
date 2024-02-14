# Lightweight C++ Webserver

## Author
Sumeet Singh

## Dated
22/01/2024

## Description
Lightweight C++ web server library for serving requests with webpages.

## License
This project is licensed under the MIT License.

Note: This project includes components from OpenSSL, which is licensed under the Apache License. See the `./src/openssl/license.txt` file for details on the Apache License.


# Requirements
OpenSSL installed on device
For Windows;
* "Win64 OpenSSL v3.2.0" found here: https://slproweb.com/products/Win32OpenSSL.html


# Installation
1. Follow the instructions in the "Example" section.
Optional: Executable/Binary can be created with CMake. 

e.g. Windows OS, using MinGW64;
Run both commands in terminal after each other in the ./build folder

```cpp
cmake .. -G "MinGW Makefiles"
mingw32-make VERBOSE=1
```


# Files
* ./src - Third party libraries
* ./website-example - Default example website
* ./wasm-example - Default example C++ WebAssembly website
* ./headers - headers
* ./headers/lightweight_cpp_webserver.hpp - Declaration file
* lightweight_cpp_webserver.cpp - Definition file
* custom_openssl_context.hpp - Declaration/Definition file
* main.cpp - Implementation file
* main.exe - Executable
* testing - Google Test environment


# Example
1. Clone or download a copy of the lightweight web server codebase 
from here: https://github.com/SumeetSinghJi/cpp-webserver

2. Initialise an object with an IP address for web server and port number
e.g; lightweight_cpp_webserver server("127.0.0.1", 8080);
The IP will then be available to browse to from a web browser

3. In handle_static_file_request() and serve_error_page() replace string ".website-example/" 
with a directory containing new website. String ".website-example/" represents a example directory that hosts example website that is loaded by default. Replace this string with any directory to load webpages within 

4. In get_requested_page() replace strings "index.html" and "homepage.html" with desired
webpage for required website.

5. Re-run the executable/binary main.exe

6. From a client browser browse to specified webserver IP:Port e.g; 127.0.0.1:8080

7. Webpage from chosen directory will load on browser.
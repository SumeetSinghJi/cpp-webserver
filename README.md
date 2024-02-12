## Lightweight C++ Webserver

## Author
Sumeet Singh

## Dated
22/01/2024

## Description
Lightweight C++ web server library for serving requests with webpages.

## License
This project is licensed under the MIT License. See the full license text in the `full_license.txt` file.

Note: This project includes components from OpenSSL, which is licensed under the Apache License. See the `license.txt` file for details on the Apache License.


## Requirements
Minimum C++ Standard: C++11
* PENDING - Uses "Win64 OpenSSL v3.2.0" found here: https://slproweb.com/products/Win32OpenSSL.html
* PENDING - Uses "boost.asio" found here: https://github.com/boostorg/asio
* OPTIONAL - CMake - to build the executable/binary if desired


## Installation
Executable/Binary can be created with CMake. 

e.g. Windows OS, using MinGW64;

Run both commands in terminal after each other in the ./build folder

```cpp
cmake .. -G "MinGW Makefiles"
mingw32-make VERBOSE=1
```

## Files
* ./src - Contains custom and/or third party libraries
* ./website-example - Default example website and webpage files serving static page
* ./wasm-example - Default example C++ WebAssembly files (.html, .js, .wasm) for testing
* ./headers - headers files for class and function declarations
* lightweight_cpp_webserver.cpp - Implementation file
* main.cpp - main file with example on how to initialise class
* main.exe - Windows OS ready executable


## Example
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

5. Webpage from chosen directory will load on browser.
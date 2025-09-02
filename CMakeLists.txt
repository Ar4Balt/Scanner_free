cmake_minimum_required(VERSION 3.10)
project(StealthScanner)

set(CMAKE_CXX_STANDARD 17)

find_package(nlohmann_json 3.2.0 REQUIRED)

add_executable(scanner scanner.cpp)
target_link_libraries(scanner PRIVATE nlohmann_json::nlohmann_json pthread)
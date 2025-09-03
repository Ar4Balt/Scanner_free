cmake_minimum_required(VERSION 3.10)
project(StealthScanner)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

file(GLOB SOURCES
    src/*.cpp
)

add_executable(scanner ${SOURCES})

target_link_libraries(scanner pthread)

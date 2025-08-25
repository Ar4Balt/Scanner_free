cmake_minimum_required(VERSION 3.15)
project(NetworkScannerProject LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Установим флаги компилятора (пример для Clang)
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wformat=2
        -Wcast-align
        -Wconversion
        -Wsign-conversion
        -Wnull-dereference
        -g3
        -O0
    )
endif()

# Укажите исходные файлы проекта
set(SOURCES
    main.cpp
    NetworkScanner.cpp
    OutputUtils.cpp
)

add_executable(NetworkScanner ${SOURCES})

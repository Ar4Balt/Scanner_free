cmake_minimum_required(VERSION 3.10)
project(StealthScanner)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Пути к заголовочным файлам
include_directories(include)

# Список исходников
set(SOURCES
    src/main.cpp
    src/scanner.cpp
)

add_executable(scanner ${SOURCES})

# pthread для Linux/macOS
if(UNIX)
    target_link_libraries(scanner pthread)
endif()

# Winsock для Windows
if(WIN32)
    target_link_libraries(scanner ws2_32)
endif()

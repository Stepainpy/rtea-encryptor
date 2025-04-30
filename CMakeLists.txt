cmake_minimum_required(VERSION 3.27)
project(rt256 VERSION 0.1 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_COLOR_MAKEFILE OFF)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR})

include_directories(inc)
file(GLOB SOURCES "src/*.c")

add_executable(${PROJECT_NAME} ${SOURCES})
target_compile_options(
    ${PROJECT_NAME} PRIVATE -Wall -Wextra -pedantic
)
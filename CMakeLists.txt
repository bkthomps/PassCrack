cmake_minimum_required(VERSION 3.14)
project(PassCrack)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -Wpedantic -O3")

add_executable(PassCrack src/PassCrack.cpp src/PassCrack.h)

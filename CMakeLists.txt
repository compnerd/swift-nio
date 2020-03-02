cmake_minimum_required(VERSION 3.16.1)

project(NIO
  LANGUAGES C Swift)

set(CMAKE_Swift_MODULE_DIRECTORY ${CMAKE_BINARY_DIR}/swift)

find_package(dispatch CONFIG)

add_subdirectory(Sources)

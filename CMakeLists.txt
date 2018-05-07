cmake_minimum_required(VERSION 3.9)
project(ndnfirewall)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Og -g")

file(GLOB LOGGER_SOURCES log/*.cpp)
file(GLOB NETWORK_SOURCES network/*.cpp)
file(GLOB TREE_SOURCES tree/*.cpp)
set(SOURCE_FILES main.cpp ndn-firewall.cpp pit.cpp pit_entry.cpp)

find_package(Boost COMPONENTS system filesystem chrono thread REQUIRED)

find_library(ndn-cxx REQUIRED)
find_library(pthread REQUIRED)

add_executable(ndnfirewall ${SOURCE_FILES} ${LOGGER_SOURCES} ${NETWORK_SOURCES} ${TREE_SOURCES})

target_link_libraries(ndnfirewall ndn-cxx ${Boost_LIBRARIES} pthread)

cmake_minimum_required(VERSION 2.6)

project(pcap-writer-test)

include_directories(.. signal-handler)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pedantic -Wall -Wextra -Wundef -Wstrict-null-sentinel")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wformat=2 -Wdisabled-optimization -Wfloat-equal -Wnon-virtual-dtor")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Woverloaded-virtual")

add_executable(write-from-file WriteFromFile.cpp ../PcapWriter.cpp signal-handler/SignalHandler.cpp)
add_executable(write-from-device WriteFromDevice.cpp ../PcapWriter.cpp)

target_link_libraries(write-from-file -lpcap)
target_link_libraries(write-from-device -lpcap)

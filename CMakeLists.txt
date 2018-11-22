cmake_minimum_required(VERSION 2.6)

project(pcap-writer)

message(STATUS "Looking for PCAP")
find_library(PCAP_LIBRARY
	NAMES pcap
	DOC "PCAP Library")
if(NOT PCAP_LIBRARY)
	message(FATAL_ERROR "PCAP not found")
endif()

# Adds CPP files to global CPP_LIST property
get_property(VAR_CPP_LIST GLOBAL PROPERTY CPP_LIST)
set_property(GLOBAL PROPERTY CPP_LIST
	${VAR_CPP_LIST}
	pcap-writer/PcapWriter.cpp)

# Adds header files to global HEADER_LIST property
get_property(VAR_HEADER_LIST GLOBAL PROPERTY HEADER_LIST)
set_property(GLOBAL PROPERTY HEADER_LIST
	${VAR_HEADER_LIST}
	pcap-writer/PcapWriter.h)

# Adds test files to global TEST_LIST property
get_property(VAR_TEST_LIST GLOBAL PROPERTY TEST_LIST)
set_property(GLOBAL PROPERTY TEST_LIST
	${VAR_TEST_LIST}
	pcap-writer/test/WriteFromFile.h
	pcap-writer/test/WriteFromDevice.h
	pcap-writer/test/WriteFromFile.cpp
	pcap-writer/test/WriteFromDevice.cpp)

install(FILES PcapWriter.h DESTINATION include/sadehghan)

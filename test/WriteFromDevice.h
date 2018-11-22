#ifndef WRITE_FROM_DEVICE_H_
#define WRITE_FROM_DEVICE_H_

#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <fcntl.h>

#include "PcapWriter.h"

/// This test's program version.
const std::string version = "1.0.2";

/// Structure to store command line parameters.
struct cmd_parameters
{
	cmd_parameters();

	/// Number of packets to capture
	int num_packet_capture;

	/// Output file path
	std::string output_file_name;
};

/// Prints how to use write from device test.
void print_usage(char* program_name);

/**
 * This method captures packets and writes them to pcap file.
 *
 * @param writer Our pcap writer library for writing captured packets to file.
 * @param num_packet_capture Number of packets to capture.
 * @param handle Pcap handler to capture.
 *
 * @return Total number of bytes has been written to file.
 */
long int capture(PcapWriter& writer, int num_packet_capture, pcap_t** handle);

/**
 * Parses command line arguments, and fills the given cmd_parameters struct fields.
 *
 * @param argc Number of command line arguments.
 * @param argv Command line arguments.
 * @param parameters Structure of cmd_parameters to fill.
 *
 * @return True if parsing successfully; otherwise false.
 */
bool parse_command_line(int argc, char** argv, cmd_parameters* parameters);

/**
 * Initials capturer. Finds available network interface and initials it to capture packets.
 *
 * @param handle The capturer device handler.
 * @return True if initializing successfully; otherwise false.
 */
bool init_capturer_device(pcap_t** handle);

/**
 * Opens output file to writing on.
 *
 * @param output_stream File stream of opened output file.
 * @param path The output file creation path.
 * @param writer Pcap writer to write pcap header.
 *
 * @return True if output file has been opened and pcap header written to it successfully;
 * 	otherwise false.
 */
bool open_writer(std::fstream* output_stream, std::string path, PcapWriter& writer);

/**
 * Closes pcap device handle and output file stream.
 *
 * @param output_stream The output file stream.
 * @param handle The capturer device handler.
 */
void close_writer(std::fstream* output_stream, pcap_t** handle);

#endif

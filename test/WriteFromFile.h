#ifndef WRITE_FROM_FILE_H_
#define WRITE_FROM_FILE_H_

#include <csignal>
#include <cstdlib>
#include <map>
#include <iomanip>
#include <iostream>
#include <pcap.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <fstream>

#include "signal-handler/SignalHandler.h"
#include "PcapWriter.h"

using namespace std;

/// Structure to store command line parameters.
struct cmd_parameters
{
	cmd_parameters();

	/// Input file path
	const char* input_file;

	/// Output file path
	const char* output_file;
};

map<int, int> signals;

/// Signal handler which keep number of caught signals
void signal_handle(int signal_number);

/// Prints content of data
void dump_hex(const unsigned char* data, unsigned int size);

/// Prints how to use write from file test.
void print_usage(char* program_name);

/**
 * Parses command line arguments, and fills the given cmd_parameters struct fields.
 *
 * @param argc Number of command line arguments.
 * @param argv Command line arguments.
 * @param parameters Struct of cmd_parameters to fill.
 *
 * @return True if parsing successfully; otherwise false.
 */
bool parse_command_line(int argc, char** argv, cmd_parameters* parameters);

#endif

#include "WriteFromDevice.h"

#include <sys/stat.h>
#include <unistd.h>

#include <fstream>
#include <iostream>

using namespace std;

cmd_parameters::cmd_parameters()
: num_packet_capture(50)
, output_file_name("out.pcap")
{
}

void print_usage(char* program_name)
{
	printf("\n\n This program has been written to test pcap file writer's library.\n");
	printf(" Usage : %s -n <NUM> -f <PATH> -h\n\n", program_name);
	printf("\t[-n <NUM>]\t: Number of packets to capture.\n");
	printf("\t[-f <PATH>]\t: Output path.\n");
	printf("\t[-h]\t\t: This help menu.\n\n");
}

long int capture(PcapWriter& writer, int num_packet_capture, pcap_t** handle)
{
	const u_char* packet;
	pcap_pkthdr header;
	long int total_len = 0;

	// Capture loop
	for (int i = 0; i < num_packet_capture; ++i)
	{
		packet = pcap_next(*handle, &header);
		if (packet == nullptr)
		{
			printf("NULL Packet!\n");
			continue;
		}

		writer.write_packet((const char*)packet, header.len, header.ts);
		/*
		 * To see captured packets uncomment the code below.
		 * printf("Packet #%5d captured \tlen:%5d\n", (i + 1), header.len);
		 */
		total_len += header.len;
	}

	return total_len;
}

bool parse_command_line(int argc, char** argv, cmd_parameters* parameters)
{
	int cmds = 0;

	while ((cmds = getopt(argc, argv, "n:f:h:v")) != -1)
	{
		switch (cmds)
		{
			case 'n':
				parameters->num_packet_capture = atoi(optarg);
				break;
			case 'f':
				parameters->output_file_name = optarg;
				break;
			case 'v':
				printf("Pcap writer test program version: %s\n.", version.c_str());
				return false;
			case '?':
			case 'h':
			default:
				print_usage(argv[0]);
				return false;
		}
	}

	return true;
}

bool init_capturer_device(pcap_t** handle)
{
	char* dev = nullptr;
	char err_buff[PCAP_ERRBUF_SIZE];

	// Look up available network capturer device
	dev = pcap_lookupdev(err_buff);
	if (dev == nullptr)
	{
		printf("Device not found !\n");
		printf("Error: %s\n", err_buff);
		return false;		// Return error
	}

	if (strcmp(dev, "eth0") != 0)
	{
		printf("Device type not supported !\n");
		printf("Device type :\"%s\"\n", dev);
		return false;		// Return error
	}

	printf("Device found : %s\n", dev);		// Print device type

	*handle = pcap_open_live(dev, BUFSIZ, 1, 0, err_buff);
	if (*handle == nullptr)		// Check capturer handle
	{
		printf("Can't open live !\n");
		printf("Error : %s\n", err_buff);
		return false;		// Return error
	}

	return true;
}

bool open_writer(std::fstream* output_stream, std::string path, PcapWriter& writer)
{
	// Opens file for writing if exists and create one if not.
	output_stream->open(path.c_str(), std::fstream::out);
	if (!output_stream->good())
	{
		cerr << "Could not open output file for Pcap Writer!" << endl;
		return EXIT_FAILURE;
	}

	chmod(path.c_str(), 0666);

	if (writer.write_pcap_header(output_stream, 1) < 0)		// Link type 1 = Ethernet
	{
		printf("Error in write_pcap_header()\n");		// Print appropriate error if Writing header to file failed.
		printf("\tout : %s \n", path.c_str());		// Print FD
		return false;		// Return error
	}

	return true;
}

void close_writer(std::fstream* output_stream, pcap_t** handle)
{
	output_stream->close();		// Close output file
	pcap_close(*handle);		// Close input pcap file
}

/**
 * Main function and entry point of this program.
 *
 * Main function takes the command line arguments and parses them, then creates a handler for capturer device.
 * After that creates and opens an output file, and starts capturing packets and writes them in pcap formatted output
 * file.
 */
int main(int argc, char* argv[])
{
	// PcapWriter object for testing library
	PcapWriter writer;

	pcap_t* handle = nullptr;
	cmd_parameters parameters;
	constexpr int pcap_header_size = 24;
	long int total_size;
	std::fstream out;

	if (!parse_command_line(argc, argv, &parameters))
		return 1;

	if (!init_capturer_device(&handle))
		return 1;

	if (!open_writer(&out, parameters.output_file_name, writer))
		return 1;

	total_size = capture(writer, parameters.num_packet_capture, &handle) + pcap_header_size;

	close_writer(&out, &handle);

	printf("\nTotally %ld bytes written to '%s'.\n", total_size, parameters.output_file_name.c_str());
	return EXIT_SUCCESS;		// Return successfully
}

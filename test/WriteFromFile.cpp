#include "WriteFromFile.h"

cmd_parameters::cmd_parameters()
: input_file("")
, output_file("out.pcap")
{
}

void signal_handle(int signal_number)
{
	map<int, int>::iterator itr = signals.find(signal_number);
	if (itr != signals.end())
		++signals[signal_number];
	else
		signals[signal_number] = 1;
}

void dump_hex(const unsigned char* data, unsigned int size)
{
	for (unsigned int i = 0; i < size; ++i)
	{
		if (i % 16 == 0)
		{
			if (i == 0)
				cout << setfill('0') << setw(4) << hex << i << "\t";
			else
				cout << endl << setfill('0') << setw(4) << hex << i << "\t";
		}
		else if (i % 8 == 0)
			cout << "\t";

		cout << setfill('0') << setw(2) << hex << data[i] << ' ';
	}

	cout << endl << "---------------------------" << endl;
}

void print_usage(char* program_name)
{
	printf("\nThis program has been written to test pcap file writer's library.\n");
	printf(" Usage : %s -i <input_file> -o <output_file> -h\n\n", program_name);
	printf("\t-i <input_file>\t: Input file name.\n");
	printf("\t[-o <output_file]>\t: Output file name.\n");
	printf("\t[-h]\t\t: This help menu.\n\n");
}

bool parse_command_line(int argc, char** argv, cmd_parameters* parameters)
{
	int cmds = 0;

	while ((cmds = getopt(argc, argv, "i:o:h")) != -1)
	{
		switch (cmds)
		{
			case 'i':
				parameters->input_file = optarg;
				break;
			case 'o':
				parameters->output_file = optarg;
				break;
			case '?':
			case 'h':
			default:
				print_usage(argv[0]);
				return false;
		}
	}

	if (!strcmp(parameters->input_file, ""))
	{
		print_usage(argv[0]);
		return false;
	}

	return true;
}

int main(int argc, char** argv)
{
	// Register all signal types you want to handle.
	SignalHandler::add_handler_to_signals(signal_handle, {SIGINT, SIGTERM, SIGKILL, SIGALRM});

	cmd_parameters parameters;
	if (!parse_command_line(argc, argv, &parameters))
		return 1;

	// Output file name of Pcap Writer library starts with writer_
	const string writer_file_name = "writer_" + string(parameters.output_file);

	char err_buffer[PCAP_ERRBUF_SIZE];
	pcap_t* const handle = pcap_open_offline(parameters.input_file, err_buffer);
	if (!handle)
	{
		cerr << "Could not open pcap file : '" << err_buffer << "'." << endl;
		return EXIT_FAILURE;
	}

	pcap_dumper_t* dumper = pcap_dump_open(handle, parameters.output_file);
	if (dumper == nullptr)
	{
		cerr << "Could not open file for dumping!" << endl;
		return EXIT_FAILURE;
	}

	/*
	 * Opens output file for Pcap Writer
	 * 0666 means user, group and others have read and write permission on this file.
	 */
	std::fstream output_stream;
	output_stream.open(writer_file_name.c_str(), std::fstream::out);
	if (!output_stream.good())
	{
		cerr << "Could not open output file for Pcap Writer!" << endl;
		return EXIT_FAILURE;
	}

	chmod(writer_file_name.c_str(), 0666);

	PcapWriter writer;
	writer.write_pcap_header(&output_stream, 1);		// Link type 1 = Ethernet

	const unsigned char* pkt = nullptr;
	pcap_pkthdr* pkthdr = nullptr;
	unsigned long long writer_total_bytes = 0;
	unsigned long long packet_count = 0;
	unsigned long long caplen = 0;
	unsigned long long len = 0;

	// Reads packet.
	while (pcap_next_ex(handle, &pkthdr, &pkt) >= 0)
	{
		// Gathers this packet statistics.
		++packet_count;
		len += pkthdr->len;
		caplen += pkthdr->caplen;

		// Writes Packet to file.
		pcap_dump(reinterpret_cast<u_char*>(dumper), pkthdr, pkt);
		writer_total_bytes += writer.write_packet(reinterpret_cast<const char*>(pkt), pkthdr->caplen, pkthdr->ts);

		/*
		 * Dump content in hex formated.
		 * To print all the packets information, uncomment lines below.
		 * cout << "Packet number : " << dec << packet_count << endl;
		 * cout << "len : " << setfill(' ') << setw(5) << pkthdr->len
		 *	 << " captured len : " << setw(5) << pkthdr->caplen << endl << endl;
		 * dump_hex(pkt, pkthdr->caplen);
		 */
	}

	cout << endl;
	cout << "Captured packets     : " << dec << packet_count << endl;
	cout << "Captured length      : " << caplen << endl;
	cout << "Real length          : " << len << endl;
	cout << "Pcap Writer total length : " << writer_total_bytes + 24 << endl;

	/*
	 * Size of pcap_pkthdr is 16 bytes.
	 * Size of pcap_file_header is 24 bytes.
	 * Total file size is caplen + size of pcap_file_header + (size of pcap_pkthdr * packet_count).
	 */
	cout << "Output size must be: " << (caplen  + 24 + (16 * packet_count)) << endl;
	cout << signals.size() << " signal(s) handled :" << endl;
	for (map<const int, int>::value_type& signal : signals)
		cout << "signal " << signal.first << " caught " << signal.second << " times." << endl;
	output_stream.close();
	pcap_dump_close(dumper);
	pcap_close(handle);

	return EXIT_SUCCESS;
}

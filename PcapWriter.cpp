#include "PcapWriter.h"

PcapWriter::PcapWriter()
: pcap_output(nullptr)
{
}

bool PcapWriter::write_buffer(const void* buffer, size_t count)
{
	if (!pcap_output)
		return false;

	const char* temp_buffer = reinterpret_cast<const char*>(buffer);

	std::streamsize bytes_written = 0;
	errno = 0;
	while (count > 0)
	{
		if ((bytes_written = pcap_output->rdbuf()->sputn(temp_buffer, static_cast<std::streamsize>(count))) <= 0)
		{
			if (errno != EINTR && errno != EAGAIN)
				return false;

			continue;
		}

		count -= static_cast<size_t>(bytes_written);
		temp_buffer += bytes_written;
	}

	return true;
}

int PcapWriter::write_pcap_header(std::fstream* file_stream, uint8_t link_type)
{
	pcap_output = file_stream;
	pcap_file_header file_header;

	// For more information about pcap_file_header struct, please read "/usr/include/pcap/pcap.h" header file.
	file_header.magic = TCPDUMP_MAGIC;		// Tcpdump magic number.
	file_header.sigfigs = 0;		// Accuracy of timestamps.
	file_header.version_major = PCAP_VERSION_MAJOR;		// Set pcap file version.
	file_header.version_minor = PCAP_VERSION_MINOR;

	file_header.snaplen = SNAPSHOT_LENGTH;
	file_header.thiszone = 0;		// GMT to local time correction.
	file_header.linktype = link_type;		// Set data link type.

	if (!write_buffer(&file_header, sizeof(file_header)))
	{
		pcap_output = nullptr;
		return -1;
	}
	// Number of bytes has been written to file (must be 24 bytes).
	return sizeof(file_header);
}

int PcapWriter::write_packet(const char* frame, uint16_t frame_size, timeval time)
{
	// Pcap record header
	pcaprec_hdr_t packet_header;

	// Fills per-record header.
	packet_header.len = frame_size;
	packet_header.caplen = frame_size;
	packet_header.ts_sec = static_cast<uint32_t>(time.tv_sec);
	packet_header.ts_usec = static_cast<uint32_t>(time.tv_usec);

	// Writes pcap record header.
	if (!write_buffer(&packet_header, sizeof(packet_header)))
		return -1;

	// Writes pcap data.
	if (!write_buffer(frame, frame_size))
		return -2;

	// Number of bytes has been written to file.
	return static_cast<int>(frame_size + sizeof(packet_header));
}

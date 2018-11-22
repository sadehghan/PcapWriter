#ifndef PCAP_WRITER_H_
#define PCAP_WRITER_H_

#include <cerrno>
#include <cstdint>

#include <fstream>

#include <pcap.h>

/**
 * This class provides well-defined interface for writing network captured data to pcap file. The output file must be
 * opened by user application, and that file descriptor is used for writing data to output file. The pcap file has a
 * global header and followed by zero or more data records for each captured packet. Global header starts at the
 * beginning of pcap file and will be followed by the first packet header. Every packet starts with record (packet)
 * header (any byte alignment is possible). The actual packet data will immediately follow record (packet) header.
 *
 * For more information about pcap file format see "http://wiki.wireshark.org/Development/LibpcapFileFormat", and 
 * "/usr/include/pcap/pcap.h" header file and pcap man page.
 */
class PcapWriter
{
public:
	PcapWriter();

	/**
	 * Writes global header to the beginning of pcap file. You must use this function before writing any captured
	 * packet data to the pcap file.
	 *
	 * @param file_stream The output file stream.
	 * @param link_type Data link layer type (1 = Ethernet).
	 * @return -1 for failure or number of bytes has been written to the file (header size = 24bytes) for success.
	 */
	int write_pcap_header(std::fstream* file_stream, uint8_t link_type);

	/**
	 * Writes packet info to file. Per-record (packet) header will be created by the given input parameters
	 * (frame_size and time parameters). It fills per-record header, writes packet header, and packet data,
	 * all together in the specified pcap output file.
	 *
	 * @param frame Packet data shall to be written in pcap file.
	 * @param frame_size Length of packet.
	 * @param time Captured packet's timestamp.
	 * @return Number of bytes written to the file.
	 *	"header size=24 bytes + frame size" if succeed,
	 *	"-1" if writing packet header be failed.
	 *	"-2" if writing data frame be failed.
	 */
	int write_packet(const char* frame, uint16_t frame_size, timeval time);

private:
	/**
	 * Magic number is used to detect file format ordering, the writing application writes 0xA1B2C3D4 and the reading
	 * application reads this field, if swapped (0xD4C3B2A1) reads all the following fields in little-endian ordering.
	 */
	constexpr static uint64_t TCPDUMP_MAGIC = 0xa1b2c3d4;

	/**
	 * A snapshot length of 65535 should be sufficient, on most if not all networks, to capture all the data
	 * available from the packet. For more information, please read pcap man page.
	 */
	constexpr static uint32_t SNAPSHOT_LENGTH = 65535;

	/**
	 * Writes all the buffer contents in the output file.
	 *
	 * @param buffer Content of the buffer.
	 * @param count Number of bytes that you want to be written in the specified output file.
	 * @return True for success and false for failure to write.
	 */
	bool write_buffer(const void* buffer, size_t count);

	/// Pcap recorded packet header
	struct pcaprec_hdr_t
	{
		/// Timestamp seconds
		uint32_t ts_sec;

		/// Timestamp microseconds
		uint32_t ts_usec;

		/// Number of packet bytes saved in file
		uint32_t len;

		/// Actual length of packet
		uint32_t caplen;
	} __attribute__((packed));

	/// Output file stream for this pcap writer
	std::fstream* pcap_output;
};

#endif

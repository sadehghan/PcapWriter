# PcapWriter

This class provides well-defined interface for writing network captured data to pcap file. The output file must be
opened by user application, and that file descriptor is used for writing data to output file. The pcap file has a
global header and followed by zero or more data records for each captured packet. Global header starts at the
beginning of pcap file and will be followed by the first packet header. Every packet starts with record (packet)
header (any byte alignment is possible). The actual packet data will immediately follow record (packet) header.

For more information about pcap file format see "http://wiki.wireshark.org/Development/LibpcapFileFormat", and 
"/usr/include/pcap/pcap.h" header file and pcap man page.


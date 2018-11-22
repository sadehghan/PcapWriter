#!/bin/bash

packet_number="$1"
output1="device_output.pcap"
output2="file_output.pcap"

# If the input arguments are not correct, echo how to use script.
if [ "$packet_number" == "" ];
then
	echo "Usage : ./pcap_writer_compare_tests.sh <number_of_packets>"
	exit -1
fi

mkdir -p ./build		# Create build directory if needed. 
cd ./build		# Change current directory to build.

# If files exist, delete them.
if [ -e $output1 ]
then
	rm $output1
fi

if [ -e $output2 ]
then
	rm $output2 
fi

if [ -e writer_$output2 ]
then
	rm writer_$output2
fi

# Make and run tests with appropriate arguments.
cmake ..
make
./write-from-device  -f $output1 -n $packet_number
./write-from-file -i ./$output1 -o $output2

# Change color scheme. 1 for red, 2 for green, 3 for yellow, 4 for blue and etc.
txtred=$(tput setaf 1)
txtgreen=$(tput setaf 2)
# Reset color scheme to default. 
txtrst=$(tput sgr0)

# Compute md5sum for each file and compare them to see if they are equal or not. 
result_file1=$(md5sum ${output1} | cut -f1 -d' ')
result_file2=$(md5sum ${output2} | cut -f1 -d' ')
result_file3=$(md5sum writer_${output2} | cut -f1 -d' ')
echo "------------------------------------"
echo "md5sum of all output files : "
echo $result_file1 : Written from device 
echo $result_file2 : Written from out.pcap with libpcap 
echo $result_file3 : Written from out.pcap with PcapWriter 
if [ "$result_file1" == "$result_file2" ] && [ "$result_file2" == "$result_file3" ]
then
	echo "${txtgreen}md5sum outputs for these files are equal.${txtrst}" # Change color and reset at the end of line.
else
	echo "${txtred}md5sum outputs for these files are NOT equal.${txtrst}"

fi
echo "------------------------------------"


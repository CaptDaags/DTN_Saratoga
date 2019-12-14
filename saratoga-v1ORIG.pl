#!/usr/bin/env perl
# Saratoga client/server file transfer version-1
#
# See LICENSE-BSD2.txt for licensing information
#
# Copyright (c) 2012, David H. Stewart, William D. Ivancic
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted
# provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice, this list of conditions
# and the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright notice, this list of
# conditions and the following disclaimer in the documentation and/or other materials provided
# with the distribution.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
# POSSIBILITY OF SUCH DAMAGE.

use strict;
use warnings;
use Data::Dumper;
use POSIX;
use Socket;
use IO::Socket::INET;
use IO::Socket::Multicast;
use IO::Interface::Simple;
use Sys::Hostname;
use Time::HiRes qw{usleep gettimeofday time};
use Unix::Syslog qw(:subs :macros) ;
use Digest::MD5::File qw(dir_md5_hex file_md5_hex url_md5_hex);


openlog 'Saratoga', LOG_PID, LOG_USER;

use constant
    { SUCCESS 					=> 0x00,
      UNSPECIFIED_ERROR 			=> 0x01,
      SENDER_RESOURCE_CONSTRAINTS	 	=> 0x02,
      RCVR_RESOURCE_CONSTRAINTS 		=> 0x03,
      FILE_NOT_FOUND 				=> 0x04,
      ACCESS_DENIED 				=> 0x05,
      UNKNOWN_TRANSACTION_ID 			=> 0x06,
      FAILED_TO_DELETE_FILE 			=> 0x07,
      FILE_TO_LARGE_FOR_RCVR 			=> 0x08,
      FILE_OFFSET_DESCRIPTOR_MISMATCHED 	=> 0x09,
      UNSUPPORTED_PACKET_TYPE 			=> 0x0A,
      UNSUPPORTED_REQUEST_TYPE 			=> 0x0B,
      REQUEST_TIMEOUT				=> 0x0C,
      DATA_FLAG_BITS_CHANGED 			=> 0x0D,
      RCVR_ENDS_TRANSFER			=> 0x0E,
      FILE_IN_USE				=> 0x0F,
      METADATA_NOT_RCVD 			=> 0x10,
      STATUS_MESSAGE_RCVD                       => 0x11,

      BEACON_INTERVAL 		 => 5, # seconds
      SND_STATUS_PERIOD 	 => 8, # in seconds,
      RCV_STATUS_PERIOD 	 => 8, # in seconds, time for receiver to send status if sndr goes quiet.
      INACTIVITY_TIMEOUT 	 => 16, # in seconds, time for receiver to delete transaction if sndr goes quiet.
      SND_INACTIVITY_TIMEOUT 	 => 16, # in seconds, time for sender to delete transaction if rcvr goes quiet.
      TIMER_TO_WAIT_FOR_METADATA => 2, # in seconds, time for receiver to wait for metadata after xfer is done.
      MAX_FRAME_SIZE => 10000, # largest expected (receive) layer 2 frame

      TRANS_TYPE_SIMPLE	=> 1,
      TRANS_TYPE_DATA 	=> 2,
      MAX_NO_DESC_BITS	=> 64,		# Maximum # of descriptor bits for this application.
      MAX_DESC_BITS  	=> 0x800000,	# Flag bits 8 & 9, Sets maximum file size supported.
	DESC_16_BIT  	=> 0x000000,	#           0   0  16 bit support
	DESC_32_BIT  	=> 0x400000,	#           0   1  32 bit support
	DESC_64_BIT  	=> 0x800000,	#           1   0  64 bit support
	DESC_128_BIT 	=> 0xC00000,	#           1   1 128 bit support

      FLAG_DESC_BITS => 0xC00000,	#Flag bits 8 & 9 mask.

	# Request Type Values (bits 24 - 31)
      REQ_NO_OP     =>  0x000000,		# Request Type value for NO_OP = 0x00.
      REQ_GET       =>  0x000001,		# Request Type value for 'get' file = 0x01.
      REQ_PUT       =>  0x000002,		# Request Type value for 'put' =0x02.
      REQ_TAKE      =>  0x000003,		# Request Type value for 'take'(get+delete) = 0x03.
      REQ_GIVE      =>  0x000004,		# Request Type value for 'give'(put+delete) = 0x04.
      REQ_DELETE    =>  0x000005,		# Request Type value for 'delete'(file or dir) = 0x05.
      REQ_DIR       =>  0x000006,		# Request Type value for 'getdir' = 0x06.
      REQ_TYPE_MASK =>  0x0000FF,		# Request Type Mask (bits 24 - 31) = 0xFF.

	# Beacon Flag masks
      BEC_FLAG_BUNDLE_BIT 	=> 0x200000,	#Beacon Flag bit 10 mask.
      BEC_FLAG_STREAMS_BIT 	=> 0x100000,	#Beacon Flag bit 11 mask.
      BEC_FLAG_CW_SND_BITS 	=> 0x0C0000,	#Beacon Flag bits 12 & 13 mask.
      BEC_FLAG_CW_RCV_BITS	=> 0x030000,	#Beacon Flag bits 14 & 15 mask.
      BEC_FLAG_UDPLITE_BIT 	=> 0x008000,	#Request Flag bit 16 mask.
      BEC_FLAG_SPACE_ADV_BIT 	=> 0x004000,	#Beacon Flag bit 17 mask, Free Space Advertised bit.
      BEC_FLAG_SPACE_DESC_BIT 	=> 0x010000,	#Beacon Flag bits 18 & 19 mask, desc of Avail Free Space field.

	# Request Flag masks
      REQ_FLAG_BUNDLE_BIT => 0x200000,	#Request Flag bit 10.
      REQ_FLAG_STREAMS_BIT => 0x100000,	#Request Flag bit 11 mask.
      REQ_FLAG_DELETE_BIT => 0x020000,	#Request Flag bit 14 mask.
      REQ_FLAG_DIRECTORY_BIT => 0x010000,#Request Flag bit 15 mask. If not a directory then a file.
      REQ_FLAG_UDPLITE_BIT => 0x008000,	#Request Flag bit 16 mask.

	# Metadata Flag masks
      META_FLAG_XFER_TYPE    => 0x300000, # Metadata Flag bits 10 & 11 mask.
       META_FLAG_XFER_FILE   => 0x000000, # Metadata Flag bits 10 & 11 to indicate xfer is a file.
       META_FLAG_XFER_DIR    => 0x100000, # Metadata Flag bits 10 & 11 to indicate directory record.
       META_FLAG_XFER_BUNDLE => 0x200000, # Metadata Flag bits 10 & 11 to indicate xfer is a bundle.
       META_FLAG_XFER_STREAM => 0x300000, # Metadata Flag bits 10 & 11 to indicate xfer is a stream.

      META_FLAG_XFER_INPROGRESS => 0x080000, # Metadata Flag bit 12 indicates xfer is in progress.
      META_FLAG_XFER_UDPlite    => 0x040000, # Metadata Flag bit 13 indicates UDPlite.
      META_FLAG_XFER_SUMTYPE    => 0x00000F, # Metadata Checksum type field mask, bits 28-31.
      META_FLAG_XFER_SUMLENGTH  => 0x0000F0, # Metadata Checksum length field mask, bits 24-27.

	# Holestofill (STATUS) Flag masks
      H2F_FLAG_TIMESTAMP_MASK     => 0x00080000, # Status Flag bit 12 mask. Timestamp included.
      H2F_FLAG_META_RCVD_MASK     => 0x00040000, # Status Flag bit 13 mask. Metadata has not been recieved.
      H2F_FLAG_FULL_HOLELIST_MASK => 0x00020000, # Status Flag bit 14 mask. Incomplete hole list sent.
      H2F_FLAG_VOLUNTARY_MASK     => 0x00010000, # Status Flag bit 15 mask. Voluntarily sent packet.
      H2F_FLAG_STATUS_MASK	  => 0x000000FF, # Status Flag bits 24-31 mask, Status field.
      H2F_XFER_COMPLETE_MASK	  => 0x00070000, # Mask bits 13-15, to check Status packet indicates completion.

	# Data Flag masks
      DATA_EOD		    => 0x008000,	# End Of Data Flag, Bit 16.
      DATA_HOLE_REQUEST_BIT => 0x010000		# Hole request Flag bit 15 mask.
      };

my %error_msg = (
    0x00 => 'SUCCESS',
    0x01 => 'UNSPECIFIED_ERROR',
    0x02 => 'SENDER_RESOURCE_CONSTRAINTS',
    0x03 => 'RCVR_RESOURCE_CONSTRAINTS',
    0x04 => 'FILE_NOT_FOUND',
    0x05 => 'ACCESS_DENIED',
    0x06 => 'UNKNOWN_TRANSACTION_ID',
    0x07 => 'FAILED_TO_DELETE_FILE',
    0x08 => 'FILE_TO_LARGE_FOR_RCVR',
    0x09 => 'FILE_OFFSET_DESCRIPTOR_MISMATCHED',
    0x0A => 'UNSUPPORTED_PACKET_TYPE',
    0x0B => 'UNSUPPORTED_REQUEST_TYPE',
    0x0C => 'REQUEST_TIMEOUT',
    0x0D => 'DATA_FLAG_BITS_CHANGED',
    0x0E => 'RCVR_ENDS_TRANSFER',
    0x0F => 'FILE_IN_USE',
    0x10 => 'METADATA_NOT_RCVD',
    0x11 => 'STATUS_ERROR_RCVD'
);

$Data::Dumper::Indent = 3;
my @desc_format = ('0', 'n', 'N', '0', 'q>', '0', '0', '0', 'w'); # lookup table for 'pack' format types.
my $saratoga_port = 7542;
my $saratoga_port_multi = 7543;
my $lpa_port = 7575;
my $saratoga_multicast_addr = '224.0.0.108';
my $lpa_multicast_addr = '226.1.1.2';
my $ttl_multicast = 4; 				# TTL for sent multicast packet.
my $saratoga_protocol_version = 1;
my $flags = 0;
my $ok_to_write = 0;

# debugging varibles
my $verbose_mode	= 0 ;
my $verbose_rqt		= 0 ;
my $verbose_meta	= 0 ;
my $verbose_stat	= 0 ;
my $verbose_bec 	= 0 ;
my $verbose_data 	= 0 ;
my $verbose_iter 	= 0 ;
my $verbose_dmp		= 0 ; # data dumpers.
my $verbose_pp		= 0 ; # Place Payload subroutine.
my $verbose_fh		= 0 ; # First Hole subroutine.
my $verbose_tc		= 0 ; # Percent Complete subroutine.
my $verbose_sp		= 0 ; # Send Packet subroutine.
my $verbose_vs		= 0 ; # Voluntary Status loop in main.
my $verbose_gd		= 0 ; # Get Directory subroutine.
my $verbose_gf		= 0 ; # Get File subroutine.
my $verbose_pd		= 0 ; # Prt Directory subroutine.
my $verbose_net		= 0 ; # Get Network Info subroutine.
my $verbose_rp		= 0 ; # Receive packet subroutine.
my $verbose_del		= 0 ; # delete file subroutine.
my $verbose_sum		= 0 ; # Metadata checksum subroutine.
my $verbose_lpa		= 0 ; # Receive LPA packet subroutine.

my $en_beacon_multicast	= 0 ; # enable beacon with multicast address.
my $en_beacon_broadcast = 0 ; # enable beacon with broadcast address.
my $enable_beacon 	= $en_beacon_broadcast | $en_beacon_multicast ; # set if either beacon mode is set.

my $server_in_addr; # set via 'open' command
my $my_ip_addr;
my $eid 	 = 'Endpoint' ; # Unique Endpoint Identifier.
my $prompt = 'saratoga> ';

my $C_hostaddr; # $C_* - sara.conf variables
my $C_peeraddr;
my $C_verbose;
my $C_rate;
my $C_eid;
my $C_multicast_interface;
my $C_lpa_multicast_intf;
my $lpa_multicast_intf = 'eth0';

my $bundle_support   =	0x000000;# Flag bit 10, 0x020000 = BUNDLE support
my $streams_support  =	0x000000;# Flag bit 10, 0x010000 = STREAMS support
my $cw_snd_files     =	0x0C0000;# Flag bits 12 & 13, Capability and Willingness to send files.
my $cw_rcv_files     =	0x030000;# Flag bits 14 & 15, Capability and Willingness to receive files.
my $udplite_support  =	0x000000;# Flag bit 16, 0x008000 = UDPLITE support for REQ packet.
my $avail_space_adv  =  0x004000;# Flag bit 17, 0x004000 Available free space advertised in beacon.
my $size_space_field =	0x000000;# Flag bits 18 & 19, Size of free space field.
				 #	0x000000	0   0  16 bit support
				 #      0x001000	0   1  32 bit support
				 #	0x002000	1   0  64 bit support
				 #      0x003000	1   1 128 bit support

my $checksum_support =	0x000000;# Flag bits 28-31
				 #	0x000000 = no checksum
				 #	0x000001 = crc32
				 #	0x000002 = MD5
				 #	0x000003 = SHA-1
my $checksum_length =	0x000000;# Flag bits 24-27
				 #	0x000000 = no checksum
				 #	0x000010 =  32 bit e.g. crc32
				 #	0x000040 = 128 bit e.g. MD5
				 #	0x000050 = 160 bit e.g. SHA-1
my $allow_put_wo_metadata = 1; 	 # Set to '1' allows collection of data with out receiving metadata first.

my $rin = ''; # event bits
my $win = '';
my $ein = '';
my ($rout, $wout, $eout);

# The rate in seconds at which the event loop checks for timeout
# events.
my $tick_interval = 0.125;

my $data_payload_size = 1514 - 10 - 14 - 34;#ether packet size - data-type hdr - udp hdr - slop
my $bcast_in_addr; # to be defined in 'get_network_info' sub.
my $lastsent = gettimeofday; # time that a packet was sent last.
my $rate_limit = .01; # the time between packets sent.
my $xfer_time_left_b4_status = 0; # used in send_packet() set to # seconds left in a xfer before hole request
				  # flag is set.  Value of 0 indicates do NOT send.
my $avail_free_space = 150000000; # 1 Kbyte blocks of free storage space to be advertised in beacon.

my $sfo; 	# socket file object (IO::Handle)
my $sfo_lpa;	# socket file object for incoming Modem LPA messages.
my $sfo_multi;	# socket file object for multicast (IO::Socket::Multicast)


my %rcv_transactions;
# Hash %transactions is a set of objects that encompasses all the receive
# active transactions. The transactions in this set are indexed by an
# ID, the CRC-32 hash of a file name as defined in the Saratoga
# protocol.
#
# Transaction members are themselves hashes. Each transaction
# represents an active instance of data transfer. Each transaction
# contains these elements:
#
# $rcv_transactions{$id}{x}
#
#	{x} =	{action}		- set for 'getdir', 'get','delete'
#		{alldone}		- file has been completely rcvd, but not written
#		{authentication}	- contents of Request packets authentication field.
#		{bundle_header}		- assigned $transactions{$id}{data} when file = dtn header
#		{bundles}		- Non zero value indicates peer can receive DTN bundles.
#		{checksum}		- File checksum for metadata packet.
#		{checksum_support}	- Type of file checksum contained in metadata packet.
#		{delete_req}		- If set indicates 'delete' request transaction, else its
#					  a 'get' or 'getdir' request.
#		{descriptor}		- Flag bits 8 & 9, first used to store sent REQUEST flags,
#					  then set by rcvd METADATA flags.
#		{desc_no_bits}		- bit length of the descriptor field (16, 32, 64 or 128).
#		{data}			- blob of data to be sent or being received
#		{finish_time}		- time when transfer is completed. set in data subroutine.
#		{fragstart}		- starting location of data-bundle assoc with {spoofack}
#		{fragend}		- ending location of data-bundle assoc with {spoofack}
#		{get_filename}		- remote filename for 'get' command.
#		{holes}			- list of hole pairs of missing data for file download
#		{in_addr}		- internet address of peer. Set in 'get' & 'dir'
#					  subroutines in %handle_cmds hash.
#		{inactivity_timeout}	- timeout timer for incoming data transaction set and
#					  reset in receive{data} subroutine
#		{is_bundle}		- data-bundle, download triggered by dtn header download
#		{is_directory_list}	- flag - list directory, don't write file
#		{last_packet_rcvd}	- Time that the last data packet sent was received for a transaction.
#		{length}		- expected size of data being received
#		{metadata}		- Was metadata for this transaction received.
#		{ndatapackets}		- packet counter, used in receive{data} subroutine
#		{No_name}		- Set indicates that xfer needs a file name.
#		{no_packets}		- # of packets a file is fragmented to.	A value of zero
#					  indicates the packet is unnumbered. ie Holefill or dir.
#	        {offset}		- starting byte location that rcvd payload should be
#					  written to in transaction{$id}{data}.
#		{path_only}		- If set file path field specifies a directory.
#					   0 = file , != 0 then dir
#		{peer}			- IP address and port# of the peer, from $peer_in_addr.
#		{progress_indicator}    - The offset of the lowest-numbered octet of the file not
#					  yet received.
#		{start_time}		- time when metadata or data packet is rcvd.
#		{stat_req_cnt}		- # of requested status packets sent.
#		{stat_req_hole_cnt}	- Total # of holes sent by request.
#		{stat_vol_cnt}		- # of voluntary status packets sent.
#		{stat_vol_hole_cnt}	- Total # of holes sent voluntarily.
#		{status_flags}		- Save flags 8, 9 & 12 from rcvd data packet for future status packets.
#		{streams}		- Non zero value indicates peer can receive data streams.
#		{time}			- ???
#*		{timestamp_nonce}	- sent by Sender in data packet then echoed back in the
#					  holestofill (status) packet from the Receiver.
#		{UDPlite}		- Non zero value indicates peer can receive UDP-lite.
#		{write_filename}	- name of file to be written (if get...)

my %snd_transactions;
# Hash %transactions is a set of objects that encompasses all the
# active transactions being sent. The transactions in this set are indexed by an
# ID, the CRC-32 hash of a file name as defined in the Saratoga
# protocol.
#
# Transaction members are themselves hashes. Each transaction
# represents an active instance of data transfer. Each transaction
# contains these elements:
#
# $snd_transactions{$id}{x}
#
#	{x} =	{action}		- set for 'getdir', 'get','delete'
#		{authentication}	- contents of Request packets authentication field.
#		{bundle_header}		- assigned $transactions{$id}{data} when file = dtn header
#		{bundles}		- Non zero value indicates peer can receive DTN bundles.
#		{checksum}		- File checksum for metadata packet.
#		{delete_req}		- If set indicates 'delete' request transaction, else its
#					  a 'get' or 'getdir' request.
#		{descriptor}		- Flag bits 8 & 9, first used to store rcvd REQUEST flags,
#					  then set by Sender when determining METADATA flags.
#		{desc_no_bits}		- bit length of the descriptor field (16, 32, 64 or 128).
#		{data}			- blob of data to be sent or being received
#		{finish_time}		- time when transfer is completed. set in data subroutine.
#		{fragstart}		- starting location of data-bundle assoc with {spoofack}
#		{fragend}		- ending location of data-bundle assoc with {spoofack}
#		{get_filename}		- remote filename for 'get' command.
#		{holes}			- list of hole pairs of missing data for file download
#		{in_addr}		- internet address of peer. Set in 'get' & 'dir'
#					  subroutines in %handle_cmds hash.
#		{inactivity_timeout}	- timeout timer set in incoming request transaction and
#					  reset in receive{status} subroutine.
#		{is_bundle}		- data-bundle, download triggered by dtn header download
#		{is_directory_list}	- flag - list directory, don't write file
#		{last_packet_sent}	- record of the highest # packet sent to client
#		{length}		- expected size of data being received
#		{metadata}		- directory entry for metadata packet to send to receiver.
#		{ndatapackets}		- packet counter, used in receive{data} subroutine
#		{no_packets}		- # of packets a file is fragmented to.	A value of zero
#					  indicates the packet is unnumbered. ie Holefill or dir.
#	       X{offset}		- starting byte location that rcvd payload should be
#					  written to in transaction{$id}{data}. NEVER SET!
#		{path_only}		- If set file path field specifies a directory.
#					   0 = file , != 0 then dir
#		{peer}			- IP address and port# of the peer, from $peer_in_addr.
#		{send_timestamp}	- Set to '1', if data packet is to send timestamps.
#		{sent_packets}		- packet counter counting # of packets sent for a transaction.
#		{start_time}		- time when metadata packet is rcvd.
#		{status_timer}	- timer used to pace data packets with hole request flag set.
#		{streams}		- Non zero value indicates peer can receive data streams.
#		{time}			- ???
#*		{timestamp_nonce}	- sent by Sender in data packet then echoed back in the
#					  holestofill (status) packet from the Receiver.
#*		{timestamp_nonce_reply}	- echo received from the Receiver.
#		{UDPlite}		- Non zero value indicates peer can receive UDP-lite.
#		{write_filename}	- name of file to be written (if get...)

my %stats; # Hash table to record stats on status packets of transfer.

# $stats{$id}{requested}
#		    {count}
#		    {No.}
#			{progress_indicator}
#		    	{in_response_to}
#		    	{number_holes_sent}
#			{hole_list}
# $stats{$id}{voluntary}
#		    {count}
#		    {No.}
#			{progress_indicator}
#			{in_response_to}
#			{number_holes_sent}
#			{hole_list}

my @queue;

# Array @queue is the queue of packets to be transmitted out the
# socket $sfo.  Elements of @queue represent an instance of something
# that is to be sent to the peer. The elements are themselves hashes
# and each contains these members:
#
#	X{type}		- an enumeration of TRANS_TYPE_SIMPLE or TRANS_TYPE_DATA, the latter of
#			which indicates payload that will have to be fragmented and sent in a
#			series of packets (possibly DEPRECATE)  NOT USED IN THIS IMPLEMENTATION!
#	{payload}	- the data to be sent
#	{in_addr}	- the address (in_addr_t) to which the data are to be sent
#	{blob}		- if type blob, this is the blob (DEPRECATE)
#	{offset}	- a pointer used when fragmenting blob-type payloads.
#			  Used to identify duplicate packets from holefills in @queue.
#	{id}		- Identifies the transaction that generated packet.
#	{terminate_id}	- set to transaction id if that transaction is to be
#	{terminated}	- (deleted) after sending this packet. NOT USED!

my %peers;

# Hash %peers stores Endpoint IDentifiers (EID) that are received via beacon packets or staticlly configured.
# The EID name will become the main key and will be a hash table in itself, having a set of keys that store
# information describing the peers capabilities.
#
# Below is a list of keys for the EID hash table:
# $peers{$eid}{ key* }
#
#	{address_v4}		- Array of IPv4 addresses associated with EID.
#	{address_v6}		- Array of IPv6 addresses associated with EID.
#		{lifetime}*	- Set to the time of last bacon received or '0' for static entries.
#	{bundle_support}	- Set to '1' if peer supports DTN otherwise set to '0'.
#	{stream_support}	- Set to '1' if peer supports streaming otherwise set to '0'.
#	{cw_snd_files}		- Bits 12 & 13, Set to value of masked flags for this field.
#	{cw_rcv_files}		- Bits 14 & 15, Set to value of masked flags for this field.
#	{udplite}		- Set to '1' if peer supports UDPlite otherwise set to '0'.
#	{free_space}		- Number of 1 KB blocks of storage peer is advertising as available
#	{transfer_size}		- Bits 8 & 9, Set to value of masked flags for this field.
#
# * lifetime will actually be a key attached to each address.
#    Ex. $peers{$eid}{address_v4}{$peer_address}{lifetime}

my %modem_lpa;

# Hash %modem_lpa stores modem link data. Keyed on modem ID.
#
# $modem_lpa{$modem_id}
#
#		{block_type_ID}
#		{block_length}
#		{No_links}
#		{link_rate_desc}
#		{modem_flags}
#		{Modem_ID}
#		{mtu}
#		{intf_flags}
#		{current_rate}
#		{min_rate}
#		{max_rate}
#		{modem_ipv4_addr}
#		{modem_ipv6_addr}

my %snd_packet;

# Hash %make is a set of packet making functions, indexed by packet
# type. For each defined type of Saratoga packet, there is a function
# that, given appropriate arguments, will fashion a packet of that
# type and return it as an opaque string.

my %rcv_packet;

# Hash %recv_packet is a set of receiver-handler functions. It is
# indexed by the numeric type of the packet as defined in Saratoga
# protocol. Each function, given a buffer containing the packet (an
# opaque string), will take appropriate action to handle the packet.

sub enqueue_at_front {
    # Add a packet to the queue and enable socket write
    # events. Packets at the front of the queue are sent first.
    my $a = shift;
    unshift @queue, $a;
    syslog LOG_INFO, "enqueue at front, %d octets, %d in queue\n", length($a), 1+$#queue
     if $verbose_mode;
    # print STDERR Dumper(\@queue); die "debug exit";
    vec($win, $sfo->fileno(), 1) = 1;
}

sub enqueue_and_terminate { # Client only, called from rcvd{tfrstatus} subroutine
    # Enqueue a packet to send and also mark the indicated session for
    # termination. We can't terminate until after the packet has been
    # sent, so actual termination (deletion) happens in the event loop.
    my ($elt, $id) = @_; # $elt is an outgoing holefill packet from rcvd{tfrstatus}
    $elt->{terminate_id} = $id;
    push @queue, $elt;
    # print STDERR Dumper(\@queue); die "debug exit";
    vec($win, $sfo->fileno(), 1) = 1;
}

sub enqueue_at_back {
    my $a = shift;
    push @queue, $a;
    syslog LOG_DEBUG, "enqueue at back, %d octets, %d in queue\n", length($a), 1+$#queue
     if $verbose_mode;
   # print STDERR Dumper(\@queue); die "debug exit";
    vec($win, $sfo->fileno(), 1) = 1;
}

sub ntop {
    # return IP address as a printable string
    my $in_addr = shift;
    my ($port, $ip_addr) = unpack_sockaddr_in $in_addr;
    return inet_ntoa $ip_addr;
}

############################ Get Network Info Subroutine #######################################################
sub get_network_info {
    my @interfaces = IO::Interface::Simple->interfaces;
    my $b_set =0;

    for my $if (@interfaces) {
	if  (defined $if->address && $if->is_running && !$if->is_loopback) {
	    printf "Interface: %s, Addr: %s, Bcst: %s.\n", $if, $if->address, $if->broadcast if $verbose_net;

	    $peers{$eid}{broadcast}{$if->address} = $if->broadcast;

	    if (($if->address eq $C_hostaddr) && ($b_set == 0)) { #set Broadcast address.
		my $addr = gethostbyname $if->broadcast;
		$bcast_in_addr = pack_sockaddr_in($saratoga_port, $addr);
		$b_set = 1;
		printf "BCAST set to subnet (%s).\n", ntop($bcast_in_addr) if $verbose_net;
	    }
	    else {
		if ($b_set == 0) {
		    $bcast_in_addr = sockaddr_in($saratoga_port, INADDR_BROADCAST);
		    printf "BCAST set to default.\n" if $verbose_net;
		}
	    }
	}
    }
    printf Dumper(\%{$peers{$eid}{broadcast}}) ;#, if $verbose_dmp && $verbose_net;
}
############################ End of Get Network Info Subroutine! ###############################################

sub time_to_str {
    return strftime('%F %T', localtime shift);
}

############################ PRINT HOLES Subroutine ############################################################
sub print_holes {
    my $blob = shift;
    while ($blob) {
	my ($start, $finish);
	($start, $finish, $blob) = unpack 'N N a*', $blob;
	printf " start=%8d, finish=%8d\n", $start, $finish;
    }
}
############################ End ofPRINT HOLES Subroutine ######################################################

############################ Process Status Message Subroutine #################################################
sub process_status_message {
    my ($status, $id) = @_;

    if (defined ($rcv_transactions{$id}{action}) && ($rcv_transactions{$id}{action} eq 'delete')){
	printf " Delete file error(0x%02x) from peer for transaction id: %08x,  %s. \n",
									    $status, $id, $error_msg{$status};
	delete $rcv_transactions{$id};
    }
    else {
    printf " Transfer error(0x%02x) from peer for transaction id: %08x,  %s. \n",
									    $status, $id, $error_msg{$status};
	delete $snd_transactions{$id};
    }

}
############################ End of Process Status Message Subroutine ##########################################

############################ Perform_checksum Subroutine #################################################
sub perform_checksum {
    my ($id, $checksum_support) = @_;
    printf "Executing sub perform_checksum for Id:%x, checksum # %d.\n", $id, $checksum_support if $verbose_sum;
    my $chksum;
    SWITCH: {
	if ($checksum_support == 0){
	    $chksum = '';
	    last SWITCH;}
	if ($checksum_support == 1){
	    # Need to implement CRC-32c algorithm here.
	    $snd_transactions{$id}{checksum} = '';
	    last SWITCH;}
	if ($checksum_support == 2){
	    my $md5 = Digest::MD5->new;
	    $chksum = file_md5_hex($snd_transactions{$id}{get_filename});
	    printf "MD5sum of file: %s is %s. \n",$snd_transactions{$id}{get_filename},$chksum, if $verbose_sum;
	    last SWITCH;}
	if ($checksum_support == 3){
	    # need to implement 160-bit SHA-1 here.
	    $snd_transactions{$id}{checksum} = '';
	    last SWITCH;}
	if ($checksum_support > 3){
	    $chksum = '';
	    last SWITCH;}
    } #End of SWITCH!
    $snd_transactions{$id}{checksum} = $chksum;
    printf "Exiting sub perform_checksum.\n", if $verbose_sum;
    return $chksum;
}
############################ End of Perform_checksum Subroutine ##########################################

############################ FIND % OF TRANSFER COMPLETED Subroutine ###########################################
sub percent_complete (\@$) {
    my ($hole_list_ref, $id) = @_;
    my $byte_count = 0;
    my @hp = (@$hole_list_ref);
    printf "Percent Complete - length of hole list = %d.\n", length @hp if $verbose_tc;
    for my $hole (@hp) {
	    printf "Percent Complete - Hole list = %d - %d. \n", $hole->[0], $hole->[1] if $verbose_tc;
    }
    my @hl = @$hole_list_ref;
	for my $hole (@hl) {
	    printf "Percent Complete - Hole list = %d - %d. \n", $hole->[0], $hole->[1] if $verbose_tc;

	    $byte_count = $byte_count + ($hole->[1] - $hole->[0]);

	    printf "     Byte count = %d. \n", $byte_count if $verbose_tc;
	}
    printf "Percent Complete = %d %%.\n", 100 - (100*$byte_count/$rcv_transactions{$id}{length}) if $verbose_tc;
    return 100 - (100*$byte_count/$rcv_transactions{$id}{length});
}
############################ End of FIND % OF TRANSFER COMPLETED  Subroutine ###################################

############################ FIND FIRST HOLE OFFSET Subroutine #################################################
sub first_hole {
    my @hole_list = @_;
    my $lowest = 0;
    my @hl = @hole_list;
	for my $hole (@hl) {
	    printf "First Hole - Hole list = %d - %d. \n", $hole->[0], $hole->[1] if $verbose_fh;
	    if ($hole->[0] == 0) { # First hole is start of file!
		printf "First Hole - Equals '0'! \n" if $verbose_fh;
		return $hole->[0];
	    }
	    if ($lowest == 0) { # First hole <
		$lowest = $hole->[0];
	    }
	    else {
		if ($hole->[0] < $lowest) {
		    $lowest = $hole->[0];
		}
	    }
	printf "First Hole - Start = %d, Lowest = %d. \n", $hole->[0], $lowest, if $verbose_fh;
	}
    printf "First Hole - return value = %d. \n", $lowest - 1, if $verbose_fh;
    return $lowest - 1;
}
############################ End of FIND FIRST HOLE OFFSET Subroutine ##########################################

################################# PRINT BLOB IN HEX Subroutine #################################################
sub print_blob_in_hex {
    # Print a string in hex; typically, dump packet contents
    my $blob = shift;
    my $chunk_size = 16;
    for (my $i = 0; $i < length $blob; $i += $chunk_size) {
	my ($hstr, $cstr);
	for (my $j = 0; $j < $chunk_size && $i + $j < length $blob; ++$j) {
	    my $c = substr $blob, $i + $j, 1;
	    $hstr .= sprintf '%02x ', ord $c;
	    $c =~ s/\W/./;
	    $cstr .= $c;
	}
	printf "%03x %-48s %-16s\n", $i, $hstr, $cstr; # FIXME - chunksize
    }
}
################################# End of PRINT BLOB IN HEX Subroutine ##########################################

############################################# ssend Subroutine #################################################
sub ssend  {
    # A wrapper around send(), to make for easier access to low level
    # network I/O.
    my ($payload, $flags, $in_addr) = @_;
    warn "error: invalid addr struct" if !defined($in_addr) || length($in_addr) < 16;
    if (!defined($in_addr) || length($in_addr) < 16 ){
	printf "Ssend - Flags = %08x, Address = %s.\n\n\n $payload \n\n\n", $flags, ntop($in_addr);
    }
    my ($port, $ip_addr) = unpack_sockaddr_in($in_addr);
    my $ns = $sfo->send($payload, $flags, $in_addr);
    if (!defined($ns)) {
	warn "send() failed, $!";
    }
}
################################### End of ssend Subroutine ####################################################

###################################   Send Packet Subroutine   #################################################
sub send_packet {
    printf "Send Packet - Before 'if vec'! \n" if $verbose_sp;
    if (vec($wout, $sfo->fileno(), 1)) { # Check for outbound packet
	printf "Send Packet! \n" if $verbose_sp;
	my $t = gettimeofday;
	if ($#queue >= 0) {
	    if ($t > $lastsent + $rate_limit) { # Pacing the output of packets to rate limit.
		$lastsent = $t;
		my $q0 = shift @queue;
		my $id = $q0->{id};
		printf Dumper($q0), if $verbose_bec & $verbose_dmp;
		if (exists $q0->{data}) { # adding Hole request to certain packets.
		    # If transaction is a file transfer and time left for transaction is less than
		    # $xfer_time_left_b4_status.
		    if (exists $snd_transactions{$id}{no_packets}
		    && $xfer_time_left_b4_status != 0
		    && (($snd_transactions{$id}{no_packets}-$snd_transactions{$id}{sent_packets})*$rate_limit)
										< $xfer_time_left_b4_status  )
		    {
			#  Timeout timer to set STATUS request flag.
			if ($snd_transactions{$id}{status_timer} < ($t - SND_STATUS_PERIOD)) {
			    $snd_transactions{$id}{status_timer} = $t;
			    my ($first_16_bits, $rest) = unpack 'n a*', $q0->{payload};
			    $first_16_bits = $first_16_bits | 0x01; # set bit 15, Hole list request.
			    printf "Send Packet - Set bit 15, %2x. \n",
								$first_16_bits if $verbose_sp | $verbose_stat;
			    $q0->{payload} = pack 'n a*', $first_16_bits, $rest;
			}
		    } #End of "if " !
		    else { # THIS IS A HACK!!!
			   # This was added to interoperate with SSTL's Code. It sets the Status Request flag on
			   # the last Data packet in @queue. It should be right the majority of the time, but
			   # will be wrong if multiple xfer requests are made concurrantly or if a non data
			   # packet is left in @queue.
			if ($#queue < 0) { # Last packet to send add Status request.
			    my ($first_16_bits, $rest) = unpack 'n a*', $q0->{payload};
			    $first_16_bits = $first_16_bits | 0x01; # set bit 15, Hole list request.
			    $q0->{payload} = pack 'n a*', $first_16_bits, $rest;
			}
		    }
		}

		ssend($q0->{payload}, 0, $q0->{in_addr});
		printf "Send Packet - Packet Sent! \n" if $verbose_sp;

		if (exists $q0->{id} 									&&
		    defined $snd_transactions{$id} 							&&
		    defined $snd_transactions{$id}{sent_packets}					) {
		    # BUG:
		    #"defined $snd_transactions{$id}" must be checked first, because if you do a
		    # "defined $snd_transactions{$id}{send_packets}", Perl will define the hash
		    # "$snd_transactions{$id}" in order to check if "$snd_transactions{$id}{sent_packets}"
		    # is defined.

		    # if payload has an ID associated to it, must be from a transaction.
		    # AND if "$snd_transactions{$id}{sent_packets}" is defined must be an sending trans.

		    ++$snd_transactions{$id}{sent_packets}; # Inc snd_trans' packet counter.

		    $snd_transactions{$id}{inactivity_timeout} = gettimeofday + SND_INACTIVITY_TIMEOUT;
		    # Reset snd_trans' inactivity counter.
		}

		# Server only
		if (defined $q0->{packet_belongs_to_sender}) {
		    # if outbound packet is assigned an Id update counters
		    printf "id=%08x,  last Packet=%08d, \n",$q0->{id},
		    $snd_transactions{$id}{last_packet_sent} if $verbose_mode;

		    if (($id != 0) && !defined $snd_transactions{$id}{last_packet_sent}) {
			$snd_transactions{$id}{last_packet_sent} = $q0->{packet_no};
		    }
		    else {
			if (($id != 0) &&
				($q0->{packet_no} > $snd_transactions{$id}{last_packet_sent})) {
			    $snd_transactions{$id}{last_packet_sent} = $q0->{packet_no};
			}
		    }
		} # End of "if packet belongs to the sender.
	    } # End of "Pacing the output of packets to rate limit."!
	} # End of "If queue is NOT empty."!
	else { # No packets to send
	    warn "debug: xmit queue empty\n" if $verbose_mode;
	    vec($win, $sfo->fileno(), 1) = 0;
	}
    }
}
###################################    End of Send Packet Subroutine!    #######################################

################################# DECODE REQUEST FLAGS Subroutine ##############################################
sub decode_request_flags { # decode request packet flags for sender side.
    my ($flags, $id) = @_ ;

    $snd_transactions{$id}{descriptor} = $flags & FLAG_DESC_BITS; # Descriptor bits indicates clients
			    # capablity, METADATA packet sets the descriptor size to be used.

    my $is_bundle_bit = $flags & REQ_FLAG_BUNDLE_BIT; # Bit 10
    if ($is_bundle_bit) { # Can the requestor support DTN bundles.
	$snd_transactions{$id}{bundles} = 1 ;
    }
    else {
	$snd_transactions{$id}{bundles} = 0 ;
    };

    my $is_streams_bit = $flags & REQ_FLAG_STREAMS_BIT; # Bit 11
    if ($is_streams_bit) { # Can the requestor support Streams.
	$snd_transactions{$id}{streams} = 1 ;
    }
    else {
	$snd_transactions{$id}{streams} = 0 ;
    };

    $snd_transactions{$id}{request_type} = $flags & REQ_TYPE_MASK; # bits 24 - 31

    my $is_UDPlite_bit = $flags & REQ_FLAG_UDPLITE_BIT; # Bit 16
    if ($is_bundle_bit) { # Requestor supports UDP-Lite.
	$snd_transactions{$id}{UDPlite} = 1 ;
    }
    else {
	$snd_transactions{$id}{UDPlite} = 0 ;
    }
}
############################ End of DECODE REQUEST FLAGS Subroutine ############################################

############################## CREATE_TMP_TRANSACTION Subroutine ###############################################
sub put_wo_metadata_create_tmp_transaction { # RECEIVER FUNCTION - Create temporary hash table for a file xfer.
    my ($id, $flags) = @_ ;
    printf "Create Transaction - Must be a 'put' without metadata.\n";
    $rcv_transactions{$id}{No_name} = 1 ; # Set to '1' to indicate that this file needs a name.
    $rcv_transactions{$id}{descriptor} = $flags & FLAG_DESC_BITS ;	#Flag bits 8 & 9 mask.
    SWITCH: { # From determined descriptor length, unpack 'directory entry'.
	if ($rcv_transactions{$id}{descriptor} == DESC_16_BIT){
	    $rcv_transactions{$id}{desc_no_bits} = 16 ;
	    $rcv_transactions{$id}{length} = 2**$rcv_transactions{$id}{desc_no_bits};
	    last SWITCH;
	}
	if ($rcv_transactions{$id}{descriptor} == DESC_32_BIT){
	    $rcv_transactions{$id}{desc_no_bits} = 32 ;
	    $rcv_transactions{$id}{length} = 2**$rcv_transactions{$id}{desc_no_bits};
	    last SWITCH;
	}
	if ($rcv_transactions{$id}{descriptor} == DESC_64_BIT){
	    $rcv_transactions{$id}{desc_no_bits} = 64 ;
	    $rcv_transactions{$id}{length} = 2**$rcv_transactions{$id}{desc_no_bits};
	    last SWITCH;
	}
	if ($rcv_transactions{$id}{descriptor} == DESC_128_BIT){
	    $rcv_transactions{$id}{desc_no_bits} = 128 ;
	    $rcv_transactions{$id}{length} = 2**$rcv_transactions{$id}{desc_no_bits};
	    last SWITCH;
	}
    } # End of SWITCH.
    # Hole pair is set to max size of descriptor, will need to be reset when metadata is rcvd.
    my $thishole = [0 , $rcv_transactions{$id}{length}];
    push (my @new_hole_list, $thishole);
    push (@{$rcv_transactions{$id}{holes}}, @new_hole_list);
    printf "\nCreate Transaction - Stored Hole list:\n", if $verbose_meta;
	    for my $hole (@{$rcv_transactions{$id}{holes}}) {
		    printf "     hole: %d - %d. \n", $hole->[0], $hole->[1] if $verbose_meta
		}
    $rcv_transactions{$id}{action} = 'get'; # 'put' and 'get' are same.
    $rcv_transactions{$id}{in_addr} = $server_in_addr;
    $rcv_transactions{$id}{write_filename} = $id;
    $rcv_transactions{$id}{start_time} = gettimeofday;
    $rcv_transactions{$id}{inactivity_timeout} = gettimeofday + INACTIVITY_TIMEOUT;

    printf "Create Transaction - Filename: %s, Descriptor bits = %d, File size = %d.\n",
	    $rcv_transactions{$id}{write_filename}, $rcv_transactions{$id}{desc_no_bits},
							    $rcv_transactions{$id}{length}, if $verbose_meta;
}
############################ End of CREATE_TMP_TRANSACTION Subroutine ##########################################

################################# GET METADATA INFO Subroutine #################################################
sub get_metadata_info { # SERVER FUNCTION - Get information about a file.
    my ($peer_in_addr, $id ) = @_ ;
    my $properties = 0x8000; # Directory entry properties field.

    printf "Send Metadata - Get metadata on Id = %08x, file '%s'. \n", $id, $snd_transactions{$id}{get_filename}
											    if $verbose_meta;
    my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks) =
								     stat($snd_transactions{$id}{get_filename});
    printf "Send Metadata - Id = %08x, file = %d bytes. \n", $id, $size if $verbose_meta;

    # Change epoch time to reference January 1, 2000.
    $atime -= 946684800 ;
    $mtime -= 946684800 ;
    $ctime -= 946684800 ;

    $snd_transactions{$id}{length} = $size;
    SWITCH: {
	    if ($size < 65536){
		$snd_transactions{$id}{descriptor} =  DESC_16_BIT;
		$snd_transactions{$id}{desc_no_bits} = 16 ;
		$snd_transactions{$id}{metadata} =pack 'n n N N', $properties | 0x0000, $size, $mtime, $ctime;
		last SWITCH;
		}
	    if ($size < 4294967296){ #commented out for interoperability with sstl
		$snd_transactions{$id}{descriptor} =  DESC_32_BIT;
		$snd_transactions{$id}{desc_no_bits} = 32 ;
		$snd_transactions{$id}{metadata} =pack 'n N N N', $properties | 0x0040, $size, $mtime, $ctime;
		printf "Get Metadata - Desc flag= %08x, size = %d bits, mtime = %d, ctime = %d. \n",
		    $snd_transactions{$id}{descriptor}, $snd_transactions{$id}{desc_no_bits}, $mtime,
		    $ctime if $verbose_meta;
		last SWITCH;
		}
	    if ($size < 18446744073709551616){
		if ($snd_transactions{$id}{descriptor} <= MAX_DESC_BITS){
		    $snd_transactions{$id}{descriptor} =  DESC_64_BIT;
		    $snd_transactions{$id}{desc_no_bits} = 64 ;
		    $snd_transactions{$id}{metadata} = pack 'n q> N N', $properties | 0x0080, $size, $mtime,
													$ctime;
		    last SWITCH;
		}
		else {
#			send_error
		    return;
		}
	    }
	    if ($size < 340282366920938463463374607431768211456){
		if ($snd_transactions{$id}{descriptor} <= MAX_DESC_BITS){
		    $snd_transactions{$id}{descriptor} = DESC_128_BIT;
		    $snd_transactions{$id}{desc_no_bits} = 128 ;
		    $snd_transactions{$id}{metadata} = pack 'n w N N', $properties | 0x00C0, $size, $mtime,
													$ctime;
		    last SWITCH;
		}
		else {
		    # send error packet
		    return;
		}
	    }
    } # End of SWITCH!
    $snd_transactions{$id}{metadata} .= pack 'A*', $snd_transactions{$id}{get_filename};
}
################################# End of GET METADATA INFO Subroutine ##########################################

################################# GETDIR METADATA  Subroutine ##################################################
# SERVER FUNCTION - Get metadata information about a directory.
sub getdir_metadata {
    my ($peer_in_addr, $id) = @_;

    my $properties = 0x8100; # Directory entry properties field indicating filename is a directory.

    printf "GetDir Metadata - Get metadata on Id = %08x, dir %s. \n", $id, $snd_transactions{$id}{get_filename}
												 if $verbose_gd;
    my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks) =
	stat($snd_transactions{$id}{get_filename});

    printf "GetDir Metadata - Id = %08x, file = %d bytes. \n", $id, $size if $verbose_gd;

    # Change epoch time to reference January 1, 2000.
    $atime -= 946684800 ;
    $mtime -= 946684800 ;
    $ctime -= 946684800 ;



    $size = $snd_transactions{$id}{length};
    SWITCH: {
	    if ($size < 65536){
		$snd_transactions{$id}{descriptor} =  DESC_16_BIT;
		$snd_transactions{$id}{desc_no_bits} = 16 ;
		$snd_transactions{$id}{metadata} =pack 'n n N N', $properties | 0x0000, $size, $mtime, $ctime;
		last SWITCH;
	    }
	    if ($size < 4294967296){
		$snd_transactions{$id}{descriptor} =  DESC_32_BIT;
		$snd_transactions{$id}{desc_no_bits} = 32 ;
		$snd_transactions{$id}{metadata} =pack 'n N N N', $properties | 0x0040, $size, $mtime, $ctime;
		printf "Get Metadata - Desc flag= %08x, size = %d bits, mtime = %d, ctime = %d. \n",
		    $snd_transactions{$id}{descriptor}, $snd_transactions{$id}{desc_no_bits}, $mtime, $ctime
											    if $verbose_meta;
		last SWITCH;
	    }
	    else {
		delete $snd_transactions{$id};
		printf "warning: Directory listing is checking greater than 4 Gbytes! \n";
		# send error packet
		return;
	    }
    } # End of SWITCH!
    $snd_transactions{$id}{metadata} .= pack 'A* x', $snd_transactions{$id}{get_filename};
}
################################# End of GETDIR METADATA  Subroutine ###########################################

#####################################  Delete File Subroutine  #################################################
sub delete_file {
    my ($peer_in_addr, $id, $file, $flags) = @_ ;
    my $status;
    if (unlink($file)) {
	printf "File deleted successfully.\n", if $verbose_del;
	$status = SUCCESS ; # status bits set to 0x00, Success.
    }
    else {
	print "File was not deleted.\n", if $verbose_del;
	$status = FILE_NOT_FOUND; # status bits set to 0x04, File not found error
    }
    $flags = ($flags & FLAG_DESC_BITS) | H2F_FLAG_VOLUNTARY_MASK; # Flags set for rejection STATUS packet.
    my $progress_indicator = 0x0000;
    my $in_response_to = 0x0000;
    my $hp_to_send;
    my $sent_by_sender =1;
    enqueue_at_front($snd_packet{status}($peer_in_addr, $flags, $status, $id, $progress_indicator,
								$in_response_to, $hp_to_send, $sent_by_sender));
}
##################################  End of Delete File Subroutine  #############################################

##################################### GET DIRECTORY Subroutine #################################################
sub get_dir { # SERVER Function.
    my ($peer_in_addr, $id, $dir_name) = @_ ;
    my $flags = $snd_transactions{$id}{descriptor};

    opendir(my $dh, $dir_name) || do {
	$flags = ($flags & FLAG_DESC_BITS) | 0x010000 ; # Flags set for rejection STATUS packet.
	my $status = FILE_NOT_FOUND ; # status bits set to 0x04, unspecified error
	my $progress_indicator = 0x00000000 ;
	my $in_response_to = 0x00000000 ;
	my $hp_to_send = 0 ;

	enqueue_at_front($snd_packet{status}($peer_in_addr, $flags, $status, $id,
			$progress_indicator, $in_response_to, $hp_to_send));

	print STDERR "debug: Directory $dir_name could not be opened! \n";
	return;
	# TODO - send back error status - may be finished 2/3/2010 dhs
    };
    for my $fn (sort readdir $dh) {
	my $pn = "$dir_name/$fn";
	my $properties = 0x00;
	printf "debug: read filename - '%s'\n", $pn if $verbose_gd;

	if (-e $pn) { # (-e $pn) - if file $pn exists?
	    if (-d $pn) { $properties = $properties | 0x0100;} # check if $pn is a directory.
	    my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks) = stat($pn);

	    printf "Get Dir - Id = %08x, file = %d bytes. \n", $id, $size if $verbose_gd;

	    # Change epoch time to reference January 1, 2000.
	    $atime -= 946684822 ;
	    $mtime -= 946684822 ;
	    $ctime -= 946684822 ;

	    SWITCH: {
		if ($size < 65536){
		    $snd_transactions{$id}{data} .= pack 'n n N N', $properties|0x8000, $size, $mtime, $ctime;
		    last SWITCH;}
		if ($size < 4294967296){
		    $snd_transactions{$id}{data} .= pack 'n N N N', $properties|0x8040, $size, $mtime, $ctime;
		    last SWITCH;}
		if ($size < 18446744073709551616){
		    $snd_transactions{$id}{data} .= pack 'n q> N N', $properties|0x8080, $size, $mtime, $ctime;
		    last SWITCH;}
		if ($size < 340282366920938463463374607431768211456){
		    $snd_transactions{$id}{data} .= pack 'n w N N', $properties|0x80C0, $size, $mtime, $ctime;
		    last SWITCH;}
	    } #End of SWITCH!
	    $snd_transactions{$id}{data} .= pack 'a* x', $fn; # Add filename and null byte.

	    printf "Get Dir - %s: Properties= %04x, size = %d, mtime = %d, ctime = %d. \n",
						    $fn, $properties, $size, $mtime, $ctime if $verbose_meta;
	} # End 'if $pn is a file'!
    } # End of Sort filenames!
    closedir $dh;
    $snd_transactions{$id}{length} = length $snd_transactions{$id}{data};

    printf "Get Dir - make metadata packet for Id = %08x, Data length = %d. \n",
							    $id, $snd_transactions{$id}{length} if $verbose_gd;
#    getdir_metadata($id);  # may be redundant!
    enqueue_at_front($snd_packet{metadata}($id, $peer_in_addr));

    my $no_packets = 0;
    $flags = $snd_transactions{$id}{descriptor} | META_FLAG_XFER_DIR;
    $snd_transactions{$id}{root_data_flags} = $flags;
    # Enqueue a sequence of data packets to transfer file
    for (my $offset = 0; $offset < length $snd_transactions{$id}{data}; $offset += $data_payload_size) {

	my $fragment = substr $snd_transactions{$id}{data}, $offset, $data_payload_size;
	++ $no_packets;
	if (($offset + $data_payload_size) < length $snd_transactions{$id}{data}){
	    # This is not the last packet of the file transfer.
	    enqueue_at_back($snd_packet{data}($flags, $id, $offset, $fragment, $peer_in_addr, $no_packets));
	}
	else { # This is the last packet of the file transfer. Add End Of Data flag (EOD)!
	    enqueue_at_back($snd_packet{data}($flags | DATA_EOD | DATA_HOLE_REQUEST_BIT, $id, $offset,
									$fragment, $peer_in_addr, $no_packets));
	}
    }
}
##################################### End of GET DIRECTORY Subroutine ##########################################

########################################## GET FILE Subroutine #################################################
sub get_file { # Get the file and fragment into packets - "SERVER FUNCTION"

    my ($peer_in_addr, $id, $file_name) = @_ ;

    # Flag conditions for data packet.
    my $flags = $snd_transactions{$id}{descriptor} | META_FLAG_XFER_FILE ;
    $snd_transactions{$id}{root_data_flags} = $flags;

    printf "warning: Get File - Time is %d \n", gettimeofday if $verbose_gf;
    if (open(my $fh, '<', $file_name)) {
	read($fh, $snd_transactions{$id}{data}, -s $file_name);
	my $no_packets = 0;
	printf "warning: Get File - Time is %d \n", gettimeofday if $verbose_gf ;
	# Enqueue a sequence of data packets to transfer file
	for (my $offset = 0; $offset < length $snd_transactions{$id}{data};
		$offset += $data_payload_size) {
	    my $fragment = substr $snd_transactions{$id}{data}, $offset, $data_payload_size;
	    ++ $no_packets;
	    if (($offset + $data_payload_size) < length $snd_transactions{$id}{data}){
		# This is not the last packet of the file transfer.
		enqueue_at_back($snd_packet{data}($flags, $id, $offset, $fragment, $peer_in_addr, $no_packets));
	    }
	    else {
		# This is the last packet of the file transfer. Add End Of Data flag (EOD)!
		#
		# Hole request added for compatability with sstl implementation.
		enqueue_at_back($snd_packet{data}($flags | DATA_EOD | DATA_HOLE_REQUEST_BIT, $id, $offset,
		#							$fragment, $peer_in_addr, $no_packets));

		# enqueue_at_back($snd_packet{data}($flags | DATA_EOD, $id, $offset,
									$fragment, $peer_in_addr, $no_packets));
	    }
	    my $t = gettimeofday;
	    if ($t > ($lastsent + $rate_limit)) {
		select($rout = $rin, $wout = $win, $eout = $ein, $tick_interval);
		send_packet();
		printf "warning: Get File - sent packet! Time is %0.2d, Time to send next %0.2d \n",
								$t, ($lastsent + $rate_limit) if $verbose_gf;
	    }
	}
	printf "warning: Get File - Number of packets is %d \n", $no_packets if $verbose_gf ;
	$snd_transactions{$id}{no_packets} = $no_packets;
	$snd_transactions{$id}{sent_packets} = 0;
    }
    else {
	$flags = ($flags & FLAG_DESC_BITS) | 0x010000 ; # Flags set for rejection STATUS packet.
	my $status = FILE_NOT_FOUND ; # status bits set to 0x04, unspecified error
	my $progress_indicator = 0x00000000 ;
	my $in_response_to = 0x00000000 ;
	my $hp_to_send = 0 ;

	enqueue_at_front($snd_packet{status}($peer_in_addr, $flags, $status, $id,
			$progress_indicator, $in_response_to, $hp_to_send));
    }
    $snd_transactions{$id}{status_timer} = gettimeofday;
}
##################################### End of GET FILE Subroutine ###############################################

################################### PRINT DIRECTORY Subroutine #################################################
sub print_dir_payload {
    # print a data payload that is a directory list
    my ($peer_in_addr, $dref, $id, $flags) = @_;
    $rcv_transactions{$id}{alldone} = 1;
    my $dir = $rcv_transactions{$id}{data};
    my($size, $mtime, $ctime, $file_name);

    printf "\nTransaction with ID %x completed (%d bytes) received.\n",$id, length $rcv_transactions{$id}{data};

    # send a 'Completed transaction' STATUS packet.
    $flags = ($flags & FLAG_DESC_BITS) | H2F_FLAG_VOLUNTARY_MASK  ; # Flags set for ack STATUS packet.
    my $status = 0x000000 ; # status bits set to 0x00, no errors
    my $progress_indicator = length($$dref) ;
    my $in_response_to = length($$dref) ;
    my $hp_to_send = \@{$rcv_transactions{$id}{holes}};

    printf "Prt Dir - Transaction with ID %x completed (%d bytes) received.\n",
	$id, length($dir), if $verbose_pd;

    enqueue_at_front($snd_packet{status}($peer_in_addr, $flags, $status, $id,
					    $progress_indicator, $in_response_to, $hp_to_send ),$id);
    # for SSTL's implementation
    enqueue_at_front($snd_packet{status}($peer_in_addr, $flags, $status, $id,
					    $progress_indicator, $in_response_to -1, $hp_to_send ),$id);

    my @desc_format = ('n', 'N', 'q>', 'w'); # lookup table for 'pack' format types.

    printf "\n\nDirectory of %s:\n\n", $rcv_transactions{$id}{get_filename};
    printf "       Mtime                   Ctime              Size      F/D   Filename\n";
	while (length $dir > 0) {
	    (my $properties, $dir) = unpack 'n a*', $dir;
	    printf "Length of dir = %d.\n", length $dir if $verbose_pd;
	    my $desc_flags = (($properties >> 6) & 3); # move bits 8 & 9, to lsb and mask.
	    my $file_type =  (($properties >> 8) & 3); # move bits 6 & 7, to lsb and mask
	    my $desc = $desc_format[$desc_flags]; # set $desc = to a pack templete char.
	    printf "Prt Dir - Properties: %16b, Bits 8 & 9: %16b, Bits 6 & 7: %16b, Unpack desc: %s.\n",
						    $properties, $desc_flags, $file_type, $desc if $verbose_pd;

	    ($size, $mtime, $ctime, $file_name, $dir) = unpack "$desc N N Z* a*", $dir;
	    $mtime += 946684800 ;
	    $ctime += 946684800 ;

	    printf "Length of dir = %d.\n", length $dir if $verbose_pd;

	    if ($file_type) {
		printf " %s	%s   %12d   D    %s\n",
						    time_to_str($mtime),time_to_str($ctime), $size, $file_name;
	    }
	    else {
		printf " %s	%s   %12d   F    %s\n",
						    time_to_str($mtime),time_to_str($ctime), $size, $file_name;
	    }

	}
}
##################################### End of PRINT DIRECTORY Subroutine ########################################

###################################   Receive Packet Subroutine   ##############################################
sub receive_packet {
    my $buf;
    if (vec($rout, $sfo->fileno(), 1)) { # Check for incoming packet
	printf "debug: Received Packet! \n", if ($verbose_rp);
	my $type = 99;
	my $max_buf_len = MAX_FRAME_SIZE;
	my $peer_in_addr = $sfo->recv($buf, $max_buf_len, 0);
	my ($peer_port, $peer_ip_addr) = unpack_sockaddr_in($peer_in_addr);
	if ( $peer_ip_addr ne $my_ip_addr 								||
	     $peer_ip_addr ne $saratoga_multicast_addr							){

	    printf "debug: got traffic from %s:%d, len %d\n",
	     ntop($peer_in_addr), $peer_port, length($buf) if ($verbose_rp);
	    if (length($buf) == 0) {
		warn "warning, empty packet received";
	    }
	    else {
		$type = unpack 'C', $buf;
		my $version = $type >> 5;
		$type &= 0x1f; # strip off version bits, left with cmd type

		printf "debug: version %d, type %d\n", $version,$type if ($verbose_rp);

		if ($type <= 4) { # Valid packet types are "0 - 4" greater than 4 would be invalid.
		    $rcv_packet{$type}($buf, $peer_in_addr);
		}
		else {
		    warn "error: rec'd invalid packet type, $type\n";
		    print_blob_in_hex($buf);
		}
	    }
	}
	else {
	    warn "error: rec'd from invalid IP address, $type\n";
	    print_blob_in_hex($buf);
	}
    }
    #if (vec($rout, $sfo_multi->fileno(), 1)) {
	#my $peer_in_addr = recv ($sfo_multi, $buf, MAX_FRAME_SIZE, 0) ;
	#my ($peer_port, $peer_ip_addr) = sockaddr_in($peer_in_addr);
	#printf "debug: Received Multicast Packet from %s:%d! \n", inet_ntoa($peer_ip_addr), $peer_port,
											       #if ($verbose_rp);
    #} else { printf "debug: vec did not find multicast packet! \n", if (0);}
}
###################################    End of Receive Packet Subroutine!    ####################################

###################################   Receive LPA Packet Subroutine   ##########################################
sub receive_LPA_packet {
    if (vec($rout, $sfo_lpa->fileno(), 1)) { # Check for incoming packet
	printf "LPA: Received LPA Packet! \n", if ($verbose_lpa);
	my $buf;
	my $max_buf_len = MAX_FRAME_SIZE;
	my $peer_in_addr = $sfo_lpa->recv($buf, $max_buf_len, 0);
	my ($peer_port, $peer_ip_addr) = unpack_sockaddr_in($peer_in_addr);
	printf "debug: got traffic from %s:%d, len %d\n", ntop($peer_in_addr), $peer_port, length($buf) if ($verbose_lpa);
	if (length($buf) == 0) {
		warn "warning, empty LPA packet received\n";
	    }
	    else {
		printf "debug: process lpa info\n", if ($verbose_lpa);
		my ($block_type_ID, $block_length, $link_info, $modem_flags, 
		    $modem_id, $mtu, $interface_flags, $current_rate, $min_rate, $max_rate, $modem_ipv4_hex) = unpack 'n n n n N n n N N N N', $buf;
		
		my $no_links 		= (( $link_info >> 8 ) & 0xff); 
		my $link_rate_desc_size = ($link_info & 0xff);
		    
		if ($current_rate > 0) {
		    $rate_limit = 8*($data_payload_size + 52)/($current_rate); # 8 bits to a byte * (# bytes in Payload + Header) / Rate
		    printf "Data rate of %.1f Kbps set for this server. \n" , $current_rate/1000 ;
		}
		else {
		    printf "LPA packet indicates modem rate is at 0. \n" if ($current_rate == 0);
		}

		$modem_lpa{$modem_id}{block_type_ID}	= $block_type_ID;
		$modem_lpa{$modem_id}{block_length}	= $block_length;
		$modem_lpa{$modem_id}{No_links}		= $no_links;
		$modem_lpa{$modem_id}{link_rate_desc}	= $link_rate_desc_size;
		$modem_lpa{$modem_id}{modem_flags}	= $modem_flags;
		$modem_lpa{$modem_id}{mtu}		= $mtu;
		$modem_lpa{$modem_id}{intf_flags}	= $interface_flags;
		$modem_lpa{$modem_id}{current_rate}	= $current_rate;
		$modem_lpa{$modem_id}{min_rate}		= $min_rate;
		$modem_lpa{$modem_id}{max_rate}		= $max_rate;
		$modem_lpa{$modem_id}{modem_ipv4_addr}	= $modem_ipv4_hex;
		$modem_lpa{$modem_id}{modem_ipv6_addr}	= undef;
				
		printf "debug: process lpa info\n", if ($verbose_lpa);
		printf STDERR Dumper(\%modem_lpa), if $verbose_lpa; 
	    }
	}

}
###################################    End of Receive LPA Packet Subroutine!    ################################

#######################################   PLACE_PAYLOAD SUBROUTINE   ###########################################
sub place_payload { # check that the packet's payload data fits in a hole, or at the current end

    my ($new_hole_list_ref, $offset, $endoffset, $payload, $peer_in_addr, $dref, $id) = @_;

    printf "Place Payload - offset = %d, endoffset = %d, id = %08x data length = %d. \n", $offset, $endoffset,
	$id, length($$dref) if $verbose_pp;

    if ($offset > length $$dref) {#payload belongs past end, make a hole, then append

	printf "Place Payload - old hole list is %d entries long\n %d after end (%d), make a hole, then
	 append\n", $#{$rcv_transactions{$id}{holes}} + 1, $offset, length($$dref) if $verbose_pp;

	my $thishole = [length($$dref), $offset];

	# Offset is beyond the end of the current data string insert null chars
	# between end of data string and beginning of payload.
	substr($$dref, length $$dref, $offset) = "\0" x ($offset - length $$dref);

	if ($offset + length($payload) <= $rcv_transactions{$id}{length}) {
	    $$dref .= $payload; # payload fits, append
	}
	elsif ($offset < $rcv_transactions{$id}{length}) {# end packet case!
	    # payload longer than space left, truncate and append.
	    my $writelen = $rcv_transactions{$id}{length} - $offset;
	    $$dref .= substr($payload, 0, $writelen);
	}

	my @holes = ($thishole);

	printf "\nPlace Payload - Hole pair:\n", if $verbose_pp;
	for my $hole (@holes) {
		    printf "     hole: %d - %d. \n", $hole->[0], $hole->[1] if $verbose_pp
	}
	# send a 'Hole Request' STATUS packet.
	# Flags set for 'hole request' STATUS packet.
	# TO DO - Add timestamp option.
	my $flags = $rcv_transactions{$id}{descriptor} | H2F_FLAG_VOLUNTARY_MASK | H2F_FLAG_FULL_HOLELIST_MASK ;

	if (!defined $rcv_transactions{$id}{metadata}) { # add metadata not received flag.
	    $flags = $flags | H2F_FLAG_META_RCVD_MASK;
	}
	my $status = 0x000000 ; # status bits set to 0x00, no errors
	my $progress_indicator = first_hole (@{$rcv_transactions{$id}{holes}}) ;
	my $in_response_to = $endoffset ;

	printf "Place Payload - Flags = %x, Prog. ind. = %d, In resp2 = %d.\n", $flags, $progress_indicator,
										$in_response_to if $verbose_pp;

	enqueue_at_front($snd_packet{status}($peer_in_addr, $flags, $status, $id, $progress_indicator,
	    $in_response_to, \@holes), $id);

    }# End of "if ($offset > length $$dref)"

    else { # offset does NOT point past the end of the current data string
	if ($offset == length $$dref) { # right at end, can append
	    syslog LOG_DEBUG, "debug: right at end, can append\n" if $verbose_pp;
	    if ($offset + length($payload) <= $rcv_transactions{$id}{length}) {
		$$dref .= $payload; # payload fits append
	    }
	    elsif ($offset < $rcv_transactions{$id}{length}) { # end packet case!
		# payload longer than space left, truncate and append.
		my $writelen = $rcv_transactions{$id}{length} - $offset;
		$$dref .= substr($payload, 0, $writelen);
	    }
	}
    }# End of "if ($offset > length $$dref) else"
}
#######################################  End of PLACE_PAYLOAD SUBROUTINE   #####################################

#######################################  ITER_HOLES SUBROUTINE   ###############################################
sub iter_holes {
#    my ($old_hole_list_ref, $new_hole_list_ref, $start, $finish, $dref, $id ) = @_;
    my ($new_hole_list_ref, $start, $finish, $dref, $id ) = @_;
    my @old_hole_list = (@{$rcv_transactions{$id}{holes}});


    printf "Iter Holes - Starting byte = %d, Finish byte = %d, id = %08x. \n", $start, $finish,
	$id, length($$dref) if $verbose_iter;

    my (@new_hole_list) = @{$new_hole_list_ref};
      	    # Check and update the hole list to see if this payload fits somewhere
    	    # JM has thourghly debug this section of code, all condition statements are needed.
	    printf "Iter Holes - checking the hole list\n" if $verbose_iter;

	    printf "\nIter Holes - Stored Hole list:\n", if $verbose_iter;
	    for my $hole (@{$rcv_transactions{$id}{holes}}) {
		    printf "     hole: %d - %d. \n", $hole->[0], $hole->[1] if $verbose_iter
		}
	    printf "\nIter Holes - Old Hole list:\n", if $verbose_iter;
	    for my $hole (@old_hole_list) {
		    printf "     hole: %d - %d. \n", $hole->[0], $hole->[1] if $verbose_iter
		}
	    printf "\nIter Holes - New Hole list:\n", if $verbose_iter;
	    for my $hole (@new_hole_list) {
		    printf "     hole: %d - %d. \n", $hole->[0], $hole->[1] if $verbose_iter
		}

	    ITER_HOLES:
		for my $hole (@old_hole_list) {
		    printf "\nIter Holes - DEBUG: testing new data over %d-%d vs old hole at %d-%d\n",
						    $start, $finish, $hole->[0], $hole->[1] if $verbose_iter;
		    if ($start > $hole->[0] && $finish < $hole->[1]) { # payload splits hole
			warn "Iter Holes - splitting hole\n" if $verbose_iter;
			if ($hole->[0] < $start) { # new hole before payload
			    push @new_hole_list, [$hole->[0], $start];
			    printf "     add hole %d, before payload\n", $hole->[0] if $verbose_iter;
			}
			if ($finish < $hole->[1]) { # new hole after payload
			    push @new_hole_list, [$finish, $hole->[1]];
			    printf "     add hole %d, after payload\n", $finish if $verbose_iter;
			}

		    }
		    elsif ($start <= $hole->[0] && $finish >= $hole->[1]) { # payload fills hole
			warn "Iter Holes - delete the hole" if $verbose_iter;
			print "removing hole, %d \n", $start if $verbose_iter;
		    }
		    elsif ($start >= $hole->[0] && $start <= $hole->[1]) { # End condition
		    	# payload fits in hole but leaves hole either before or after payload
			warn "Iter Holes - End condition\n" if $verbose_iter;
			if ($start != $hole->[0]) { # hole in front of payload
				push @new_hole_list, [$hole->[0], $start];
				printf "     add hole %d, before payload\n", $hole->[0] if $verbose_iter;
			}
			if ($finish < $hole->[1]) { # hole after payload
				push @new_hole_list, [$finish, $hole->[1]];
				printf "     add hole %d, after payload\n", $finish if $verbose_iter;
			}
		    }
		    elsif ($finish >= $hole->[0] && $finish <= $hole->[1]) { # end of payload
		    	# terminates in the middle of the hole. push new hole.
			warn "Iter Holes - End of payload\n" if $verbose_iter;
			push @new_hole_list, [$finish, $hole->[1]];
			printf "     add hole %d, after payload\n", $finish if $verbose_iter;
		    }
		    else { # payload does NOT fit into this hole, put hole back into list
			warn "Iter Holes - no overlap, just copy" if $verbose_iter;
			push @new_hole_list, $hole;
			printf "     put hole %d, back in list\n", $hole->[0] if $verbose_iter;
		    }
		} # End of hole check and update.  write new hole list.

		$rcv_transactions{$id}{holes} = \@new_hole_list;
		printf "Iter Holes - New Hole list after iterations:\n" if $verbose_iter;
		for my $hole (@new_hole_list) {
		    printf "     hole: %d - %d. \n", $hole->[0], $hole->[1] if $verbose_iter
		}
	    printf "Iter Holes - debug:length data = %d, vs file length = %d, # holes %d\n\n",length($$dref),
		    $rcv_transactions{$id}{length}, scalar(@{$rcv_transactions{$id}{holes}}) if $verbose_iter;
}
#######################################  End of ITER_HOLES SUBROUTINE   ########################################

#######################################  TRANSACTION COMPLETE SUBROUTINE   #####################################
sub file_complete {
    # We have received the entire file and there are no
    # outstanding holes. Write the file and let this
    # transaction timeout.

    my ($peer_in_addr, $dref, $id, $flags) = @_;
    $rcv_transactions{$id}{alldone} = 1;

    printf "\nTransaction with ID %x completed (%d bytes) received.\n", $id, $rcv_transactions{$id}{length};

    # send a 'Completed transaction' STATUS packet.
    $flags = ($flags & FLAG_DESC_BITS) | H2F_FLAG_VOLUNTARY_MASK  ; # Flags set for ack STATUS packet.
    my $status = 0x000000 ; # status bits set to 0x00, no errors
    my $progress_indicator = length($$dref);
    my $in_response_to = length($$dref);
    my $hp_to_send = \@{$rcv_transactions{$id}{holes}};

    printf "Transaction Completed - Transaction with ID %x completed (%d bytes) received.\n",
	$id, length($$dref), if $verbose_rqt;

    enqueue_at_front($snd_packet{status}($peer_in_addr, $flags, $status, $id,
					    $progress_indicator, $in_response_to, $hp_to_send ),$id);

    # For SSTL's implementation, their server likes to see in_resp_2 field = (filesize - 1).
    enqueue_at_front($snd_packet{status}($peer_in_addr, $flags, $status, $id,
					    $progress_indicator, $in_response_to - 1, $hp_to_send ),$id);

    my $ofpath = $rcv_transactions{$id}{write_filename};

    $rcv_transactions{$id}{finish_time} = gettimeofday;
    printf "writing file %s\n", $ofpath;
    printf "%d byte file was received in %d seconds. %.1f kbits per second.\n",
	$rcv_transactions{$id}{length},
	$rcv_transactions{$id}{finish_time} - $rcv_transactions{$id}{start_time},
	($rcv_transactions{$id}{length}*8)/
	($rcv_transactions{$id}{finish_time} - $rcv_transactions{$id}{start_time})/1000;

    # rcv_transactions hash table values:
    #	    	{stat_req_cnt}		- # of requested status packets sent.
    #		{stat_req_hole_cnt}	- Total # of holes sent by request.
    #		{stat_vol_cnt}		- # of voluntary status packets sent.
    #		{stat_vol_hole_cnt}	- Total # of holes sent voluntarily.
    printf "\n     Status packets requested from sender - %d.\n     Total # of holes sent - %d.\n
	    \n     Status packets sent voluntarily - %d.\n     Total # of holes sent - %d.\n\n",
	    $rcv_transactions{$id}{stat_req_cnt}, $rcv_transactions{$id}{stat_req_hole_cnt},
	    $rcv_transactions{$id}{stat_vol_cnt}, $rcv_transactions{$id}{stat_vol_hole_cnt};


    open(my $fh, '>', $ofpath) || do {
	syslog LOG_DEBUG, "error: open failed, %s", $!;
	# TODO - send back a failed status indication
    };
    # Write data to file ($ofpath) or bundle (/tmp/$ofpath)
    print $fh $rcv_transactions{$id}{data};
    close $fh;

    if (exists $rcv_transactions{$id}{checksum_support}) {
	my $checksum_support = $rcv_transactions{$id}{checksum_support};
	 SWITCH: {
	    if ($checksum_support == 0){
		last SWITCH;}
	    if ($checksum_support == 1){
		# Need to implement CRC-32c algorithm here.
		last SWITCH;}
	    if ($checksum_support == 2){
		my $md5 = Digest::MD5->new;
		printf "File name is >%s<! \n", $rcv_transactions{$id}{write_filename} if $verbose_rqt;
		if ($rcv_transactions{$id}{checksum} eq file_md5_hex($rcv_transactions{$id}{write_filename})){

		    printf " MD5sum of file matches that of metadata! \n";
		}
		else {
		    printf " MD5sum of file does NOT match that of metadata! \n";
		}
		last SWITCH;}
	    if ($checksum_support == 3){
		# need to implement 160-bit SHA-1 here.
		last SWITCH;}
	    if ($checksum_support > 3){
		last SWITCH;}
	} #End of SWITCH!
    }
    print STDERR "\n$prompt";
} # End if data has been completely rcvd
#######################################  End of TRANSACTION COMPLETE SUBROUTINE   ##############################

sub authenticate {
    return 0;
}

sub crc_byte {
    my ($value, $crc) = @_;
    $crc ^= $value << 24;
    for (1 .. 8) {
	if ($crc & 0x80000000) {
	    $crc = (($crc & 0x7FFFFFFF)<< 1) ^ 0x04c11db7;
	}
	else {
	    $crc <<= 1;
	}
    }
    return $crc;
}

sub calculate_crc32 {
    my $a = uc shift;
    my @cs = unpack 'C*', $a;
    my $crc = 0xffffffff;
    for my $c (@cs) {
	$crc = crc_byte($c, $crc);
    }
    syslog LOG_DEBUG, "debug: CRC of '$a' calculated as %0x8\n", $crc if $verbose_mode;
    return $crc;
}

############################ Hash Table of Packet Types ########################################################
sub no_op_Packet_Types {	} # just for a flag to be used with geany.

my %by_id = (

    0 => { # BEACON
	name => 'beacon',
	snd => sub { # ++++ SERVER FUNCTION ++++
	printf "Beacon - executing send beacon!\n", if $verbose_bec;
	my $desc; # set to a pack template character for varible length 'Available free space' field
	my $free_space; # temperary holder of packed $avail_free_space.
	if ($avail_space_adv > 0) { # Then determine size of space flags and advertise freespace available.
				    #	0x000000	0   0  16 bit support
				    #   0x001000	0   1  32 bit support
				    #	0x002000	1   0  64 bit support
				    #   0x003000	1   1 128 bit support
	    SWITCH: {
		if ($avail_free_space < 65536)
		    { $size_space_field = 0x000000; $desc = 'n'; last SWITCH; }
		if ($avail_free_space < 4294967296)
		    { $size_space_field = 0x001000; $desc = 'N'; last SWITCH; }
		if ($avail_free_space < 18446744073709551616)
		    { $size_space_field = 0x002000; $desc = 'q>'; last SWITCH; }
		if ($avail_free_space < 340282366920938463463374607431768211456)
		    { $size_space_field = 0x003000; $desc = 'w'; last SWITCH; }
	    } # End of SWITCH!
	    $free_space = pack ("$desc", $avail_free_space);
	} # End of If $avail_free_space !

	my $flags = MAX_DESC_BITS | $bundle_support | $streams_support | $cw_snd_files | $cw_rcv_files |
							$udplite_support | $avail_space_adv | $size_space_field;

	my $first_word = (($saratoga_protocol_version << 5 | 0) << 24) | $flags;
	my %r;
	$r{payload} = pack('N', $first_word).$free_space.pack('a*', $eid);
	$r{in_addr} = $bcast_in_addr;
	# $sfo_multi->mcast_send($r{payload}, "$saratoga_multicast_addr:$saratoga_port");
	printf "EID: %s, Bcst: %s\n", $eid, ntop($bcast_in_addr) if $verbose_bec;
	printf STDERR Dumper(%r), if $verbose_mode || $verbose_bec;
	return \%r;
	}, #######   End BEACON SEND!   ########################################################################

	#########   BEACON Rcvd   ##############################################################################
	rcv => sub {  # ++++ CLIENT FUNCTION ++++
	    my ($packet, $peer_in_addr) = @_;
	    my ($flags, $rest) = unpack 'N a*', $packet;
	    my $afs_size; # temporarily holds the value of Available Free Space field.

	    printf "Beacon - Beacon Received! \n", if $verbose_bec;

	    if (BEC_FLAG_SPACE_ADV_BIT == ($flags & BEC_FLAG_SPACE_ADV_BIT )) {#Bit 17, free space is advertied.
		# Then determine size of advertised free space (afs) flags.
		#	0x000000	0   0  16 bit support
		#  	0x001000	0   1  32 bit support
		#	0x002000	1   0  64 bit support
		#	0x003000	1   1 128 bit support
		my $afs_field_size = (($flags >> 12) & 3); # move bits 18 & 19, to lsb and mask.
		SWITCH: {
		    if ($afs_field_size == 0x00)
			{ ($afs_size, $rest) = unpack 'n a*', $rest; last SWITCH; }
		    if ($afs_field_size == 0x01)
			{ ($afs_size, $rest) = unpack 'N a*', $rest; last SWITCH; }
		    if ($afs_field_size == 0x10)
			{ ($afs_size, $rest) = unpack 'q> a*', $rest; last SWITCH; }
		    if ($afs_field_size == 0x11)
			{ ($afs_size, $rest) = unpack 'w a*', $rest; last SWITCH; }
		} # End of SWITCH!
	    }# End of IF free space is advertised!

	    my $eid = unpack 'a*', $rest; # Endpoint IDentifier.
	    my $t = gettimeofday;
	    $peers{$eid}{transfer_size} = $flags & FLAG_DESC_BITS;
	    $peers{$eid}{free_space} = $afs_size;
	    $peers{$eid}{udplite} = $flags & BEC_FLAG_UDPLITE_BIT;
	    $peers{$eid}{bundle_support} = $flags & BEC_FLAG_BUNDLE_BIT;
	    $peers{$eid}{stream_support} = $flags & BEC_FLAG_STREAMS_BIT;
	    $peers{$eid}{cw_snd_files} = $flags & BEC_FLAG_CW_SND_BITS;
	    $peers{$eid}{cw_rcv_files} = $flags & BEC_FLAG_CW_RCV_BITS;
	    %{$peers{$eid}{address_v4}} = ($peer_in_addr, $t);

	    printf Dumper(\%peers), if $verbose_dmp && $verbose_bec;
	}, #########   End of BEACON Rcvd!   ###################################################################
    },

    1 => { # REQUEST - command to perform either a _get_, _getdir_, or _delete_ transaction.
	name => 'request',
	snd => sub {  # ++++ CLIENT FUNCTION ++++
	    my ($my_ip_addr, $id, $remote_filename, $peer_in_addr) = @_;
	    my $flags;
	    $rcv_transactions{$id}{inactivity_timeout} = gettimeofday + INACTIVITY_TIMEOUT;

	    my $sw = $rcv_transactions{$id}{action};
	    SWITCH: { # Set Request-type field bits 24 - 31.
		if ($sw eq 'no-op')  {$flags = REQ_NO_OP;  last SWITCH;} # REQ_NO_OP  => 0x000000
		if ($sw eq 'get')    {$flags = REQ_GET;    last SWITCH;} # REQ_GET    => 0x000001
		if ($sw eq 'put')    {$flags = REQ_PUT;    last SWITCH;} # REQ_PUT    => 0x000002
		if ($sw eq 'take')   {$flags = REQ_TAKE;   last SWITCH;} # REQ_TAKE   => 0x000003
		if ($sw eq 'give')   {$flags = REQ_GIVE;   last SWITCH;} # REQ_GIVE   => 0x000004
		if ($sw eq 'delete') {$flags = REQ_DELETE; last SWITCH;} # REQ_DELETE => 0x000005
		if ($sw eq 'getdir') {$flags = REQ_DIR;    last SWITCH;} # REQ_DIR    => 0x000006
	    }

	    $flags = $flags|$bundle_support|$streams_support|$udplite_support|MAX_DESC_BITS;

	    printf "Snd Request - %s request, Flags = %08x, Bundle support = %08x, Stream support = %08x,
	    UDPlite support = %08x Max desc bits = %08x\n", $sw, $flags, $bundle_support, $streams_support,
							    $udplite_support, MAX_DESC_BITS, if $verbose_rqt;


	    my $first_word = (($saratoga_protocol_version << 5 | 1) << 24) | $flags;

	    printf "Snd Request - First word = %08x, id = %08x, filename = %s, \n", $first_word, $id,
									      $remote_filename, if $verbose_rqt;
	    my %r;
	    $r{payload} = pack('N N a* x', $first_word, $id, $remote_filename);
	    if (defined $rcv_transactions{$id}{authentication}) { # add authentication string.
		$r{payload} .= $rcv_transactions{$id}{authentication};
	    }
	    $r{in_addr} = $peer_in_addr;
	    $r{id} = $id;
	    printf "Snd Request - in_addr=%s, \n", ntop($r{in_addr}), if $verbose_rqt;
	    $rcv_transactions{$id}{start_time} = gettimeofday;

	    return \%r;
	}, #####    End of REQUEST Send!   #####################################################################

	#########   REQUEST Rcvd   #############################################################################
	rcv => sub {  # ++++ SERVER FUNCTION ++++
	    # Received a REQUEST packet, will decode the flag field and take apprpriate action.
	    #
	    # THINGS TO DO:
	    #  1. Check that it is not a duplicate request.
	    #  2. Validate Id.

	    my ($packet, $peer_in_addr) = @_;
	    my ($flags, $id, $rest) = unpack 'N N a*', $packet;

	    $flags = $flags & 0x00ffffff;
	    printf "Request Rcvd - Flags = %06x, id = %08x, Remaining bytes = %s, \n", $flags, $id, $rest,
		if $verbose_rqt;

	    decode_request_flags ($flags, $id);

	    if ($rest =~ /\0/ ) { # get File Path and Auth. Field data from rest of the packet.
		$snd_transactions{$id}{get_filename} = $`; # set {get_filename} = to string before null byte.
		printf "Request Rcvd - 'snd_transactions{id}{get_filename}' = %s \n",
							$snd_transactions{$id}{get_filename}, if $verbose_rqt;
		$snd_transactions{$id}{authentication} = $'; # set to string after null byte.
		printf "Request Rcvd - Filename = %s, Authentication String = %s \n", $`, $', if $verbose_rqt;

		if ( ! -r $snd_transactions{$id}{get_filename} ) { # -r checks if file is readable.
		    printf "warning: File or Directory '%s' is unreadable or does not exist! \n",
									   $snd_transactions{$id}{get_filename};
		    my $status = ACCESS_DENIED; # status bits set to  0x05, file not readable.
		    if ( ! -e $snd_transactions{$id}{get_filename} ) { # -e checks if file exists.
			$status = FILE_NOT_FOUND; # status bits set to 0x04, file not found.
		    }
		    my $flags =  H2F_FLAG_VOLUNTARY_MASK; # Voluntary flag set for rejection STATUS packet.
		    my $progress_indicator = 0x00000000;
		    my $in_response_to = 0x00000000;
		    my $hp_to_send;
		    my $sent_by_sender =1;
		    $snd_transactions{$id}{desc_no_bits} = 16;
		    enqueue_at_front($snd_packet{status}($peer_in_addr, $flags, $status, $id,
					   $progress_indicator, $in_response_to, $hp_to_send, $sent_by_sender));
		    delete $snd_transactions{$id};
		    return;
		}
# 	TODO - implement authenticate() later.
		if (length $snd_transactions{$id}{authentication} != 0 ) { # Then validate packet.
		    if (authenticate != 1) { # authentication failed, SEND ERROR!.
			printf "Request packet authentication failed! Terminating transaction. \n";
			$flags = ($flags & FLAG_DESC_BITS) | 0x010000; # Flags set for rejection STATUS packet.
			my $status = 0x000001 ; # status bits set to 0x01, unspecified error
			my $progress_indicator = 0x00000000 ;
			my $in_response_to = 0x00000000 ;
			my $hp_to_send = 0x00;
			enqueue_at_front($snd_packet{status}($peer_in_addr, $flags, $status, $id,
							    $progress_indicator, $in_response_to, $hp_to_send));
			delete $snd_transactions{$id};
			return;
		    }
		}
#	TODO - implement later!
#		if (length $snd_transactions{$id}{get_filename} == 0) { # Sender to choose file to send.
#		    choose_file_to_send();
#		}
	    }
	    else { # No null byte in Request packet, SEND UNSPECIFIED ERROR!.
		printf "Request packet incomplete! Terminating transaction. \n";
		$flags = ($flags & FLAG_DESC_BITS) | 0x010000 ; # Flags set for rejection STATUS packet.
		my $status = 0x000001 ; # status bits set to 0x01, unspecified error
		my $progress_indicator = 0x00000000 ;
		my $in_response_to = 0x00000000 ;
		my $hp_to_send = 0x00;
		enqueue_at_front($snd_packet{status}($peer_in_addr, $flags, $status, $id,
					    $progress_indicator, $in_response_to, $hp_to_send ));
		delete $snd_transactions{$id};
		return;
	    }

	    SWITCH: {
		# 'get_file' Request Type 0x01
		if ($snd_transactions{$id}{request_type} == REQ_GET){
		    $snd_transactions{$id}{action} = "get" ;
			my $status = 0x000000 ; # status bits set to 0x00, no errors
			my $progress_indicator = 0x00000000 ;
			my $in_response_to = 0x00000000 ;
			my $hp_to_send;
			my $status_message_from_sndr = 1;
		    printf "Request Rcvd - Requested Action = %s, \n", $snd_transactions{$id}{action},
												if $verbose_rqt;
		    enqueue_at_front($snd_packet{metadata}($id, $peer_in_addr));
		    $flags = $snd_transactions{$id}{descriptor}; # Flags set for ack STATUS packet.
		    enqueue_at_front($snd_packet{status}($peer_in_addr, $flags, $status, $id,
				$progress_indicator, $in_response_to, $hp_to_send, $status_message_from_sndr));
		    get_file($peer_in_addr, $id, $snd_transactions{$id}{get_filename}) ;
		    last SWITCH;
		}
		#  'put' Request Type 0x02 unsupported.
		if ($snd_transactions{$id}{request_type} > REQ_DIR){
		    printf "Request Rcvd - Request Type 0x02 unsupported! \n" if $verbose_rqt;
		    last SWITCH;
		}
		# 'take' (get + delete) Request Type 0x03 unsupported.
		if ($snd_transactions{$id}{request_type} > REQ_DIR){
		    printf "Request Rcvd - Request Type 0x03 unsupported! \n" if $verbose_rqt;
		    last SWITCH;
		}
		# 'give' (put + delete) Request Type 0x04 unsupported.
		if ($snd_transactions{$id}{request_type} > REQ_DIR){
		    printf "Request Rcvd - Request Type 0x04 unsupported! \n" if $verbose_rqt;
		    last SWITCH;
		}
		# 'del_file' Request Type 0x05
		if ($snd_transactions{$id}{request_type} == REQ_DELETE){
		    $snd_transactions{$id}{action} =  "delete" ;
		    $snd_transactions{$id}{desc_no_bits} = 16;
		    printf "Request Rcvd - Requested Action = %s, \n", $snd_transactions{$id}{action},
												if $verbose_rqt;
		    delete_file($peer_in_addr, $id, $snd_transactions{$id}{get_filename}, $flags);
		    delete $snd_transactions{$id};
		    return;
		    last SWITCH;
		}
		# 'get_dir' Request Type 0x06
		if ($snd_transactions{$id}{request_type} == REQ_DIR){
		    $snd_transactions{$id}{action} = "getdir" ;
			my $status = 0x000000 ; # status bits set to 0x00, no errors
			my $progress_indicator = 0x00000000 ;
			my $in_response_to = 0x00000000 ;
			my $hp_to_send;
			my $status_message_from_sndr = 1;
			printf "Request Rcvd - Requested Action = %s, \n", $snd_transactions{$id}{action},
												if $verbose_rqt;
		    get_dir($peer_in_addr, $id, $snd_transactions{$id}{get_filename});
   		    $flags = $snd_transactions{$id}{descriptor}; # Flags set for ack STATUS packet.
		    enqueue_at_front($snd_packet{status}($peer_in_addr, $flags, $status, $id,
				 $progress_indicator, $in_response_to, $hp_to_send, $status_message_from_sndr));
		    last SWITCH;
		}
		# Request type unsupported.
		if ($snd_transactions{$id}{request_type} > REQ_DIR){
		    $flags = ($flags & FLAG_DESC_BITS) | H2F_FLAG_VOLUNTARY_MASK; # Flags for STATUS packet.
		    my $status = UNSUPPORTED_REQUEST_TYPE ; # status bits set to 0x0B, error
		    my $progress_indicator = 0x00000000;
		    my $in_response_to = 0x00000000;
		    my $hp_to_send;
		    enqueue_at_front($snd_packet{status}($peer_in_addr, $flags, $status, $id,
							    $progress_indicator, $in_response_to, $hp_to_send));
		    printf "Request Rcvd - Request Type %06x, unsupported! \n",
							   $snd_transactions{$id}{request_type} if $verbose_rqt;
		    last SWITCH;
		}
	    } # End of SWITCH!
	    $snd_transactions{$id}{inactivity_timeout} = gettimeofday + SND_INACTIVITY_TIMEOUT;
	} ################   End of REQUEST Rcvd!   ############################################################
    },

    2 => { # METADATA - Response to either a _get_, _getdir_, or _put_ Request.
	name => 'metadata',
	snd => sub {  # ++++ SERVER FUNCTION ++++

	    my ( $id, $peer_in_addr) = @_;
	    my ($s, $usec) = gettimeofday();
	    printf "Send Metadata - Time %0.6d, Id = %08x. \n", $usec, $id, if $verbose_meta;
	    my $flags = 0x000000;

	    # Set Flag bits 10 & 11, according to whether transaction is a 'get' file, dir, bundle or stream.
	    if ($snd_transactions{$id}{action} eq "get"){
	    }
	    else {
		if ($snd_transactions{$id}{action} eq "getdir"){
		    $flags = $flags | META_FLAG_XFER_DIR; # Set bits 10 & 11 to indicate directory record.
		}
		else {
		    if (file_is_bundle($snd_transactions{$id}{get_filename})){
			$flags = $flags | META_FLAG_XFER_BUNDLE; #bits 10 & 11 indicate file is a bundle.
		    }
		    else{
			if (file_is_stream($snd_transactions{$id}{get_filename})){
			    $flags = $flags | META_FLAG_XFER_STREAM; #bits 10 & 11 indicate file is a stream.
			}
		    }
		}
	    }

	    # Set Flag bit 12, transfer is in progress.
	    if (defined $snd_transactions{last_packet_sent}){
		$flags = $flags | META_FLAG_XFER_INPROGRESS #Flag bit 12 indicates xfer is in progress.
	    }

	    # Set Flag bit 13, UDPlite support.
	    if ($snd_transactions{$id}{UDPlite} || $udplite_support ){
		$flags = $flags | META_FLAG_XFER_UDPlite #Flag bit 13 indicates UDPlite support.
	    }

	    my $sw = $snd_transactions{$id}{action};

	    SWITCH: {
		if ($sw eq 'get'){
		    printf "Send Metadata - flags = %08x, Execute 'get_metadata_info' Id# %08x. \n", $flags, $id
											    if $verbose_meta;
		    $snd_transactions{$id}{metadata} = get_metadata_info($peer_in_addr, $id);
		}
		if ($sw eq 'getdir'){
		    printf "Send Metadata - flags = %08x, Execute 'getdir_metadata' Id# %08x. \n", $flags, $id
											    if $verbose_meta;
		    $snd_transactions{$id}{metadata} = getdir_metadata($peer_in_addr, $id);
		    last SWITCH;
		}
	    }


	    # Set Flag bits 8 & 9, indicating # of descriptor bits to be used, since subroutine
	    # get_metadata_info() just checked and set the descriptor to the correct value.
	    printf "Send Metadata - Descriptor flags = %08x. \n", $snd_transactions{$id}{descriptor}
											    if $verbose_meta;
	    $flags = $flags | $snd_transactions{$id}{descriptor};

	    my $chksum;
	    if ($snd_transactions{$id}{action} eq 'get' ) {
	    # Set Flag bits 28-31, indicating error-detection checksum to be used.
	    $flags = $flags | $checksum_length | $checksum_support ;
	    $chksum = perform_checksum ($id, $checksum_support);
	    }

	    my %r;
	    my $first_word = (($saratoga_protocol_version << 5 | 2) << 24) | $flags;

	    if (!defined $chksum) { # No Checksum so don't pack it.
		printf "Send Metadata - 1st word = %08x Id = %08x, Checksum = '', Meta size = %d. \n",
				    $first_word, $id, length $snd_transactions{$id}{metadata} if $verbose_meta;
		$r{payload} = pack('N N a* x', $first_word, $id, $snd_transactions{$id}{metadata});
	    }
	    else { # Pack checksum!
		printf "Send Metadata - 1st word = %08x Id = %08x, Checksum = '%s', Meta size = %d. \n",
			    $first_word, $id, $chksum, length $snd_transactions{$id}{metadata} if $verbose_meta;
		$r{payload} = pack('N N H* a* x', $first_word, $id, $chksum, $snd_transactions{$id}{metadata});
	    }
	    $r{id} = $id;
	    $r{in_addr} = $peer_in_addr;
	    return \%r;
	}, # End of METADATA Send!

	########   METADATA Rcvd.   ############################################################################
	rcv => sub {  # ++++ CLIENT FUNCTION ++++  # Receive METADATA packet.

	    my ($packet, $peer_in_addr) = @_;
	    my ($s, $usec) = gettimeofday();
	    my $properties = 0x0000; # Flag registor for Directory Entry attached to METADATA packet.

	    my ($flags, $id, $rest) = unpack 'N N a*', $packet;
	    printf "Rcvd Metadata - Time %0.6d, 1st word = %08x Id = %08x, Meta size = '%d'. \n",
		$usec, $flags, $id, length $rest if $verbose_meta;
	    $flags = $flags & 0x00ffffff;

	    if (!exists $rcv_transactions{$id}) { # Metadata for a unrequest transaction initiate rcv varibles.
		$rcv_transactions{$id}{action} = 'get';
		$rcv_transactions{$id}{start_time} = gettimeofday;
		$rcv_transactions{$id}{inactivity_timeout} = gettimeofday + INACTIVITY_TIMEOUT;
		printf "Rcvd Metadata - Must be a put command.\n";
	    }

	    if (!defined $rcv_transactions{$id}{No_name}) {# If this hash table entry is defined, then the
		# transaction has been initiated w/o metadata and flags have already been set.
		# So don't overwrite them.

		# Set $rcv_transactions{$id}{descriptor} value to what the sender determined.
		$rcv_transactions{$id}{descriptor} = $flags & FLAG_DESC_BITS ;	#Flag bits 8 & 9 mask.

		# NOT decoding bits 10 & 11 yet.
		# META_FLAG_XFER_TYPE   = 0x300000, # Metadata Flag bits 10 & 11 mask.
		# META_FLAG_XFER_FILE   = 0x000000, # Metadata Flag bits 10 & 11 to indicate xfer is a file.
		# META_FLAG_XFER_DIR    = 0x100000, # Metadata Flag bits 10 & 11 to indicate directory record.
		# META_FLAG_XFER_BUNDLE = 0x200000, # Metadata Flag bits 10 & 11 to indicate xfer is a bundle.
		# META_FLAG_XFER_STREAM = 0x300000, # Metadata Flag bits 10 & 11 to indicate xfer is a stream.
		#
		# NOT decoding bit 12 yet. META_FLAG_XFER_INPROGRESS = 0x080000,
		# Metadata Flag bit 12 indicates xfer is in progress. (only for streaming)

		# Metadata Flag bit 13 indicates UDPlite.
		$rcv_transactions{$id}{UDPlite} = $flags | META_FLAG_XFER_UDPlite ;
	    }

	    if (( my $checksum_length = ($flags & META_FLAG_XFER_SUMLENGTH)) != 0 ) { # NOT PRESENTLY USED!
		#determine checksums length, then strip off checksum value from $rest and store.
		printf "Rcvd Metadata - Sum length field is set to %d, for %d bits .\n",
							  $checksum_length, 32*$checksum_length if $verbose_sum;
		$rcv_transactions{$id}{checksum_length} = $checksum_length;
	    } # End of 'if (checksum_length)'

	    if (( my $checksum_support = ($flags & META_FLAG_XFER_SUMTYPE)) != 0 ) {
		#determine checksums length, then strip off checksum value from $rest and store.
		printf "Rcvd Metadata - Checksum flags are set to %x, a non-zero value.\n",
									    $checksum_support, if $verbose_sum;
		$rcv_transactions{$id}{checksum_support} = $checksum_support;
		SWITCH: {
		if ($checksum_support == 0){
		    last SWITCH;}
		if ($checksum_support == 1){
		    # CRC-32c algorithm 32 bits.
		    $rcv_transactions{$id}{checksum} = "";
		    last SWITCH;}
		if ($checksum_support == 2){
		    # md5 checksum 128 bits.
		    my $md5 = Digest::MD5->new;
		    ($rcv_transactions{$id}{checksum}, $rest) = unpack 'H[32] a*', $rest;
		    printf " Rcvd Metadata - MD5sum of file: %s is %s. \n",$rcv_transactions{$id}{get_filename},
							    $rcv_transactions{$id}{checksum}, if $verbose_sum;
		    last SWITCH;}
		if ($checksum_support == 3){
		    # 160-bit SHA-1 160 bits
		    $rcv_transactions{$id}{checksum} = "";
		    last SWITCH;}
		if ($checksum_support > 3){
		    last SWITCH;}
		} #End of SWITCH!
	    } # End of 'if (checksum_support)'

	    SWITCH: { # From determined descriptor length, unpack 'directory entry'.
		if ($rcv_transactions{$id}{descriptor} == DESC_16_BIT){
		    $rcv_transactions{$id}{desc_no_bits} = 16 ;
		    ($rcv_transactions{$id}{properties}, $rcv_transactions{$id}{length},
		    $rcv_transactions{$id}{mtime}, $rcv_transactions{$id}{ctime},
		    $rcv_transactions{$id}{file_path})  =  unpack 'n n N N A*', $rest;
		    last SWITCH;
		}
		if ($rcv_transactions{$id}{descriptor} == DESC_32_BIT){
		    $rcv_transactions{$id}{desc_no_bits} = 32 ;
		    ($rcv_transactions{$id}{properties}, $rcv_transactions{$id}{length},
		     $rcv_transactions{$id}{mtime}, $rcv_transactions{$id}{ctime},
		    $rcv_transactions{$id}{file_path})=  unpack 'n N N N A*', $rest;
		    printf "Rcvd Metadata - Desc = 32 bits, File length = %d, mtime = %d, ctime = %d,
			properties = %01x. \n", $rcv_transactions{$id}{length}, $rcv_transactions{$id}{mtime},
			$rcv_transactions{$id}{ctime}, $rcv_transactions{$id}{properties} if $verbose_meta;
		    last SWITCH;
		}
		if ($rcv_transactions{$id}{descriptor} == DESC_64_BIT){
		    $rcv_transactions{$id}{desc_no_bits} = 64 ;
		    ($rcv_transactions{$id}{properties}, $rcv_transactions{$id}{length},
		     $rcv_transactions{$id}{mtime}, $rcv_transactions{$id}{ctime},
		     $rcv_transactions{$id}{file_path})=  unpack 'n q> N N A*', $rest;
		     printf "Rcvd Metadata - Desc = 64 bits, File length = %d, mtime = %d, ctime = %d,
			properties = %01x. \n", $rcv_transactions{$id}{length}, $rcv_transactions{$id}{mtime},
			$rcv_transactions{$id}{ctime}, $rcv_transactions{$id}{properties} if $verbose_meta;
		    last SWITCH;
		}
		if ($rcv_transactions{$id}{descriptor} == DESC_128_BIT){
		    $rcv_transactions{$id}{desc_no_bits} = 128 ;
		    ($rcv_transactions{$id}{properties}, $rcv_transactions{$id}{length},
		     $rcv_transactions{$id}{mtime}, $rcv_transactions{$id}{ctime},
		     $rcv_transactions{$id}{file_path})=  unpack 'n w N N A*', $rest;
		    last SWITCH;
		}
	    }

	    if (!exists $rcv_transactions{$id}{write_filename}) { # Assume metadata is from a 'put'!
		$rcv_transactions{$id}{write_filename} = $rcv_transactions{$id}{file_path};
		printf "Rcvd Metadata - File name of 'put' is '%s'. \n", $rcv_transactions{$id}{file_path}
											       if $verbose_meta;
	    }

	    $rcv_transactions{$id}{metadata} = 1; # Metadata received!

	    if (defined $rcv_transactions{$id}{No_name} && $rcv_transactions{$id}{No_name} == 1) {
		# transaction initiated w/o metadata.
		printf "Rcvd Metadata - Transaction entry {No_name} is set to '1', updating hole list. \n"
											       if $verbose_meta;
		printf "		Length set to: %d,  2^#_of_Desc_bits = %d.\n",
		       $rcv_transactions{$id}{length}, 2**$rcv_transactions{$id}{desc_no_bits} if $verbose_meta;
		# Check to see if EOD packet was received and the correct file length was already set.
		if (!defined $rcv_transactions{$id}{length_set}) {
		    my @new_hole_list;
		    my $dref = \$rcv_transactions{$id}{data};
		    my $start = $rcv_transactions{$id}{length};
		    my $finish = 2**$rcv_transactions{$id}{desc_no_bits};
		    iter_holes (\@new_hole_list, $start, $finish, $dref, $id);
		}
		printf "\nRcvd Metadata - Blind put, Stored Hole list:\n", if $verbose_meta;
		    for my $hole (@{$rcv_transactions{$id}{holes}}) {
			printf "     hole: %d - %d. \n", $hole->[0], $hole->[1] if $verbose_meta
		    }
		$rcv_transactions{$id}{write_filename} = $rcv_transactions{$id}{file_path};
		$rcv_transactions{$id}{No_name} = 0;
		printf "Rcvd Metadata - Transaction entry {No_name} is set to '0', file name is %s. \n",
							$rcv_transactions{$id}{write_filename} if $verbose_meta;
		if (exists $rcv_transactions{$id}{alldone}) { # file xfer completed so write it!
		    my $dref = \$rcv_transactions{$id}{data};
		    file_complete ($server_in_addr, $dref, $id, $flags);
		    delete $rcv_transactions{$id};
		    return;
		}
	    }

	    if (!defined $rcv_transactions{$id}{data}) { # Have not rcvd any data packets, initiate holes list.
		my $thishole = [0 , $rcv_transactions{$id}{length}];
		push (my @new_hole_list, $thishole);
		push (@{$rcv_transactions{$id}{holes}}, @new_hole_list) ;

		for my $hole (@new_hole_list) {
		    printf "Rcvd Metadata - Hole list = %d - %d. \n", $hole->[0], $hole->[1] if $verbose_meta;
		}
	    }
	    printf Dumper(\%rcv_transactions), if $verbose_dmp && $verbose_meta;

# TODO - next part is to send a Hole fill STATUS packet if system already has rcvd part of file.
	    # Next 4 varibles are set to pass to the 'snd_packet{holefill}' subroutine.
	    # Values are set to that of an initial holetofill packet.
	    # create holetofill flags with descriptor and what the flag bits should be set to for
	    # holetofill packet after metadata was received.
	    # Assumptions:	bit 12 = 0, first holetofill no timestamp included.
	    #			bit 13 = 0, responding to metadata, so metadata received.
	    #			bit 14 = 0, first holetofill, so one big hole.
	    #			bit 15 = 1, voluntarily sent
	    #
	    # $status		bits 24-31, Status field set to 0x00, no errors
	}, # End of METADATA Rcvd!
    }, # End of METADATA !!!

######################################## DATA Sent #############################################################
    3 => { # DATA
	name => 'data',
	snd => sub {  # ++++ SERVER FUNCTION ++++
	    my ($flags, $id, $offset, $payload, $peer_in_addr, $no_packets) = @_;
	    my ($s, $usec) = gettimeofday();
	    printf "Data Sent - Time %0.6d, flags = %08x, Id# %08x. \n", $usec, $flags, $id if $verbose_data;
	    my %r;
	    $r{packet_belongs_to_sender} = 1;
	    my $first_word = (($saratoga_protocol_version << 5 | 3) << 24) | $flags;
	    $r{payload} = pack 'N N', $first_word, $id;


	    # TODO - when is a timestamp sent?  Should it be sent all the time or intermitiantly?
	    # It should be initiated here and then echoed back from the receiver in a
	    # STATUS (holes2fill) packet.
	    # add Timestamp/nonce string if it exists.
	    if (defined $snd_transactions{$id}{timestamp_nonce}) {
		$flags = $flags | H2F_FLAG_TIMESTAMP_MASK ; # Timestamp flag bit 12 mask.
		$r{payload} .= pack('a*', $snd_transactions{$id}{timestamp_nonce});
	    }

	    my $i = $snd_transactions{$id}{desc_no_bits} / 16 ; # set $i to # of 16 bit bytes in descriptor.
	    my $desc = $desc_format[$i]; # set $desc = to a pack templete char.

	    printf "Data Sent - Offset = %08x, 	# of 16 bit Desc bytes = %d. \n", $offset, $i
											    if $verbose_data;
	    $r{id} = $id;
	    $r{payload} .= pack "$desc a*", $offset , $payload ;
	    $r{offset} = $offset;
	    $r{in_addr} = $peer_in_addr;
	    $r{data} = 1; # enables send_packet subroutine to recognize this as a data packet.
	    return \%r;
	}, # End of DATA Send!

################################### DATA Rcvd. #################################################################
	rcv => sub {  # ++++ CLIENT FUNCTION ++++
	    # We received some data. Determine which transaction it
	    # pertains to. Fill in holes as necessary, updating the
	    # hole list for this transaction's data.

	    my ($packet, $peer_in_addr) = @_;
	    my ($s, $usec) = gettimeofday();
	    my ($desc, $i); # $desc is a pack templete char, $i is the number of 16 bit bytes in descriptor.
	    my @desc_format_local = ('n', 'N', 'q>', 'w'); # lookup table for 'pack' format types.
	    my ($flags, $id, $rest) = unpack 'N N a*', $packet;
	    $flags = $flags & 0x00ffffff;
	    printf "Data Rcvd - Time %0.6d, flags = %08x, Id# %08x. \n", $usec, $flags, $id if $verbose_data;

	    if  (!defined $rcv_transactions{$id}) { # Transaction does NOT exist
		my $status_flags = ( $flags & FLAG_DESC_BITS) | H2F_FLAG_META_RCVD_MASK
					| H2F_FLAG_VOLUNTARY_MASK | H2F_FLAG_FULL_HOLELIST_MASK ;
		# above - Flag bits 13-15 set for no metadata STATUS packet. e.g. 0x?70000, ? - bits 8 & 9.
		my $status = 0x000000 ; # status bits set to 0x00, No error.
		my $progress_indicator = 0x00000000;
		my $in_response_to = 0x00000000;

		if (	(($flags & META_FLAG_XFER_TYPE) == META_FLAG_XFER_FILE)
			&& ( $allow_put_wo_metadata == 1)		){ # if xfer type flags indicate file
		    printf "Data Rcvd - Transaction does NOT exist, assume 'put'.\n", if $verbose_data;
		    put_wo_metadata_create_tmp_transaction($id, $flags);
		    printf "Data Rcvd - Metadata has not been received yet storing data,
								Transaction id: %08x.\n", $id, if $verbose_data;
		    enqueue_at_front($snd_packet{status}($peer_in_addr, $status_flags, $status, $id,
							       $progress_indicator, $in_response_to )   ,$id);
		} # End 'if data packet is a file transfer'.
		else {
		    my $status = 0x000010 ; # status bits set to 0x00, No error.
		    enqueue_at_front($snd_packet{status}($peer_in_addr, $status_flags, $status, $id,
							       $progress_indicator, $in_response_to )   ,$id);
		    printf "Data Rcvd - Transaction does NOT exist, xfer without metadata denied.\n",
											       if $verbose_data;
		    return;
		}
	    } # End if undefined transaction.

	    if (!defined $rcv_transactions{$id}{descriptor}) { # transaction defined but metadata not received.
		my @desc_size = (16, 32, 64, 128); # lookup table for # of descriptor bits.
		$rcv_transactions{$id}{descriptor} = $flags & FLAG_DESC_BITS ;	#Flag bits 8 & 9 mask.
		my $desc_bits = (($flags & FLAG_DESC_BITS) >> 22); # mask Flag bits 8 & 9 then shift to lsb.
		$rcv_transactions{$id}{desc_no_bits} = $desc_size[$desc_bits] ;	#Flag bits 8 & 9 mask.
	    }
	    if (exists $rcv_transactions{$id}{alldone}) { # File is completely rcvd.
		if (DATA_HOLE_REQUEST_BIT == ($flags | DATA_HOLE_REQUEST_BIT)) {#Bit 15 set, Holelist requested.
		    printf "Data Rcvd - File Rcvd, discard data packet but send Status.",
									    if $verbose_data | $verbose_stat;
		    my $h2f_flags = $rcv_transactions{$id}{descriptor} | H2F_FLAG_VOLUNTARY_MASK ; # 0x010000
		    my $status = 0x000000 ; # status bits set to 0x00, no errors
		    my $progress_indicator = 0xFFFFFFFF;
		    my $in_response_to = $rcv_transactions{$id}{length} ;
		    my $hp_to_send = $rcv_transactions{$id}{holes};
		    enqueue_at_front($snd_packet{status}($peer_in_addr, $h2f_flags, $status, $id,
							    $progress_indicator, $in_response_to, $hp_to_send));
		}
		else { printf "Data Rcvd - File Rcvd, discard data packet.", if $verbose_data;}
		return;
	    }
	    $rcv_transactions{$id}{status_flags} = $flags & 0x00C80000; #Save bits 8, 9 & 12 for status packets.
	    if ($flags & H2F_FLAG_TIMESTAMP_MASK){ # Timestamp flag bit 12 mask.
		($rcv_transactions{$id}{timestamp_nonce}, $rest) = unpack 'a[16] a*', $rest;
	    }
	    if (exists $rcv_transactions{$id}{desc_no_bits}) {
		$i = $rcv_transactions{$id}{desc_no_bits}/16;# $i is the number of 16 bit bytes in descriptor.
		$desc = $desc_format[$i]; # set $desc = to a pack templete char.
	    }
	    else {
		my $desc_flags = (($flags >> 22) & 3); # move bits 8 & 9, to lsb and mask.
		$desc = $desc_format_local[$desc_flags]; # set $desc = to a pack templete char.
	    }
	    #my $desc = $desc_format[$i]; # set $desc = to a pack templete char.
	    if ($desc eq '0') { # Descriptor value is wrong. probable {desc_no_bits} is not set.
		printf "Data Rcvd - Descriptor value is wrong, discard data packet.", if $verbose_data;
		return;
	    }
	    ($rcv_transactions{$id}{offset}, my $payload) = unpack "$desc a*", $rest;

	    my $m = (substr $payload, 0, 16); # for debug purposes.
	    printf "Data Rcvd - Descriptor size = %d, offset = %d, payload size = %d, first 16 bytes = '%s'.
		\n", 2*$i, $rcv_transactions{$id}{offset}, length $payload, $m if $verbose_data;

	    if ($flags & DATA_HOLE_REQUEST_BIT) {# Data packet flag bit 15, Holes list requested, send STATUS.
		printf "Data Rcvd - Hole request Rcvd, send Status.", if $verbose_data || $verbose_stat;
		my $h2f_flags = $rcv_transactions{$id}{descriptor};
		my $status = 0x000000 ; # status bits set to 0x00, no errors
		my $progress_indicator = first_hole (@{$rcv_transactions{$id}{holes}}) ;
		my $in_response_to = $rcv_transactions{$id}{offset} ;
		my $hp_to_send = $rcv_transactions{$id}{holes};
		enqueue_at_front($snd_packet{status}($peer_in_addr, $h2f_flags, $status, $id,
							    $progress_indicator, $in_response_to, $hp_to_send));
	    }
	    if ($flags & DATA_EOD) {# End of Data flag bit 16, Holes list.
		printf "Data Rcvd - End of Data flag set!\n", if $verbose_data || $verbose_stat;
		if (exists $rcv_transactions{$id}{No_name}
			&& $rcv_transactions{$id}{No_name} == 1) { # No metadata so file length is not known.
		    $rcv_transactions{$id}{length} = $rcv_transactions{$id}{offset} + length $payload;
		    $rcv_transactions{$id}{length_set} = 1;
		    my @new_hole_list;
		    my $dref = \$rcv_transactions{$id}{data};
		    my $start = $rcv_transactions{$id}{length};
		    my $finish = 2**$rcv_transactions{$id}{desc_no_bits};
		    iter_holes (\@new_hole_list, $start, $finish, $dref, $id);
		    printf "Data Rcvd - Blind put, new file length = %d.\n",
					       $rcv_transactions{$id}{length} if $verbose_data || $verbose_stat;
		    printf "\nData Rcvd - new Hole list:\n", if $verbose_data;
		    for my $hole (@{$rcv_transactions{$id}{holes}}) {
			printf "     hole: %d - %d. \n", $hole->[0], $hole->[1] if $verbose_data
		    }
		}
	    }
	    if (!defined $rcv_transactions{$id}{data}) { # First packet of the transaction rcvd.
		$rcv_transactions{$id}{data} = ''; # Initialize $transactions{$id}{data}
		if (!defined $rcv_transactions{$id}{holes}) {
                  @{$rcv_transactions{$id}{holes}} = (); # Initialize empty hole array
                  # ??? - holes are initially set to the start and end of the file.  This is done
                  # when the 'metadata' packet is received or when subroutine receive{data}
                  # initiates a 'get' for a data-bundle. Not sure why it is here?
                }
	    }
	    my $dref = \$rcv_transactions{$id}{data};
    	    my $start = $rcv_transactions{$id}{offset};
	    my $finish = $start + length($payload);

	    printf "Data Rcvd - Starting offset = %d, Length of payload = %d, End offset = %d. \n",
		$start, length ($payload), $finish if $verbose_data;

	    printf Dumper(\%rcv_transactions), if $verbose_dmp && $verbose_data;

	    my @new_hole_list;

	    if ($finish > $rcv_transactions{$id}{length}) {
		syslog LOG_DEBUG, "warning: file exceeds previously declared length, %d > %d\n",
		 $finish, $rcv_transactions{$id}{length} if $verbose_mode;
	    }

	    syslog LOG_DEBUG, "debug: offset %d, rcvd data length %d\n", $start, length($$dref)
											    if $verbose_mode;

	    # check that this packet data fits in a hole, or at the current end and place it.
	    place_payload(\@new_hole_list, $start, $finish, $payload, $peer_in_addr, $dref, $id);

	    substr($$dref, $start, length($payload)) = $payload; # may be redundant?

	    iter_holes (\@new_hole_list, $start, $finish, $dref, $id);

	     # Update inactivity watchdog timer so transaction does not time out.
	    $rcv_transactions{$id}{inactivity_timeout} = gettimeofday + INACTIVITY_TIMEOUT;

	    # Update time of the last packet received for purpose of sending vountary status packets to sender.
	    $rcv_transactions{$id}{last_packet_rcvd} = gettimeofday;

	    # Check if data has been completely rcvd, if so process.
	    if (length($$dref)>= $rcv_transactions{$id}{length} && ($#{$rcv_transactions{$id}{holes}} < 0)) {
		# We have received the entire data set and there are no
		# outstanding holes. Write the file and let transaction
		# timeout.
		my $sw = $rcv_transactions{$id}{action};
		SWITCH: {
		    if ($sw eq 'get')	{
			printf "Data Rcvd - Xfer is complete, check if metadata was rcvd.\n", if $verbose_data;
			if (!defined $rcv_transactions{$id}{metadata} 					&&
				    ($rcv_transactions{$id}{write_filename} == $id)
			    ){# This file is from a blind _put_ without metadata so has no name yet.
			     $rcv_transactions{$id}{alldone} = 1;
			     $rcv_transactions{$id}{waiting_for_metadata} = gettimeofday;
			}
			 else {
			    file_complete ($peer_in_addr, $dref, $id, $flags);
			}
			last SWITCH;}
		    if ($sw eq 'getdir') {print_dir_payload($peer_in_addr, $dref, $id, $flags);	last SWITCH;}
		} # End of SWITCH!

	    }
	}, #########    End of DATA Rcvd!   ####################################################################
    }, # End of DATA.

    4 => { # STATUS
	name => 'status',
	snd => sub {  # ++++ CLIENT/SERVER FUNCTION ++++

	    my ($peer_in_addr, $flags, $status, $id, $progress_indicator, $in_response_to,
		$hole_pairs, $status_message_from_sndr ) = @_;
	    my ($s, $usec) = gettimeofday();
	    my @hp_to_send = defined $hole_pairs ? @{$hole_pairs} : "\0";
	    my $number_holes_sent = 0;	# for collecting stats
	    my @sent_hole_list;		# for collecting stats



	    printf "Send Status - Time %0.6d, Flags = %08x, Stat = %02x, Id = %08x, Ind = %08x, rsp2 = %08x.\n",
			   $usec, $flags, $status, $id, $progress_indicator, $in_response_to,  if $verbose_stat;
	    my %r;
	    my $first_word = (($saratoga_protocol_version << 5 | 4) << 24) | $flags | $status;
	    $r{payload} = pack('N N', $first_word, $id );

	    if (exists $rcv_transactions{$id} && exists $rcv_transactions{$id}{timestamp_nonce}) {
		# add Timestamp/nonce if it exists.
		$r{payload} .= pack('q>', $rcv_transactions{$id}{timestamp_nonce}) ;
		delete $rcv_transactions{$id}{timestamp_nonce} ;
	    }

	    my $i;
	    # when sending status for delete transaction there is no $rcv_transactions{$id}{desc_no_bits}
	    if (defined $status_message_from_sndr) {
		$i = $snd_transactions{$id}{desc_no_bits} / 16 ; # set $i to # of 16 bit bytes in descriptor
	    }
	    else {
		$i = $rcv_transactions{$id}{desc_no_bits} / 16 ; # set $i to # of 16 bit bytes in descriptor
	    }

	# Collecting data on the transfer.
	    if (!defined $status_message_from_sndr && $status == 0x00 && $#hp_to_send >= 0) { # Status packet is a hole request.
		# rcv_transactions hash table values:
		#	    	{stat_req_cnt}		- # of requested status packets sent.
		#		{stat_req_hole_cnt}	- Total # of holes sent by request.
		#		{stat_vol_cnt}		- # of voluntary status packets sent.
		#		{stat_vol_hole_cnt}	- Total # of holes sent voluntarily.

		my $hole_cnt = 2*$i*(1 + $#hp_to_send) <= $data_payload_size ? (1 + $#hp_to_send)
										: ($data_payload_size/(2*$i));

		# H2F_FLAG_VOLUNTARY_MASK => 0x00010000, # Status Flag bit 15 mask. Voluntarily sent packet.
		if (($flags & H2F_FLAG_VOLUNTARY_MASK) == H2F_FLAG_VOLUNTARY_MASK) { # Status sent voluntarily
		    ++$rcv_transactions{$id}{stat_vol_cnt};
		    $rcv_transactions{$id}{stat_vol_hole_cnt} += $hole_cnt;
		}
		else { # Status was Requested from Sender.
		    ++$rcv_transactions{$id}{stat_req_cnt};
		    $rcv_transactions{$id}{stat_req_hole_cnt} += $hole_cnt;
		}
	    } # END of Collecting data on the transfer.

	    my $desc = $desc_format[$i]; # set $desc = to a pack templete char.
	    $r{payload} .= pack("$desc $desc", $progress_indicator, $in_response_to);
	    printf "Send Status - Desc %s, Flags = %08x, Stat = %02x, Id = %08x, Ind = %08x, rsp2 = %08x.\n",
			   $desc, $flags, $status, $id, $progress_indicator, $in_response_to,  if $verbose_stat;
	    if (defined $hole_pairs) {
		# @hp_to_send = @{$hole_pairs} ;
		if ($#hp_to_send > ( - 1)) {
		    foreach my $hole (@hp_to_send) {
			print "Send Stat - sending hole: " . "@$hole" . "\n", if $verbose_stat;
			my $temp = pack "$desc $desc", @$hole;
			if (length ($temp) + length $r{payload} <= $data_payload_size){
			    $r{payload} .= $temp;
			    $number_holes_sent++ ;	# for collecting stats
			    push (@sent_hole_list, @$hole);
			}
			else {
			    printf "Send Stat - Packet is full, payload size = %d.\n",
									    length $r{payload} if $verbose_stat;
			    ($first_word, my $rest) = unpack 'N a*', $r{payload};
			    $first_word = $first_word | H2F_FLAG_FULL_HOLELIST_MASK;
			    # Set bit 14, Packet contains incomplete holelist.
			    $r{payload} = pack 'N a*', $first_word, $rest;
			    last;
			}
		    }
		}
	    }
    #	For collecting stats - Future
	#    # If status packet is not an error message, then record stats.
	#    if (!defined $status_message_from_sndr && $status == 0x00) {
	#	if (!defined $stats{$id}) { # if not defined initiate.
	#	    $stats{$id}{requested}{count} = 0;
	#	    $stats{$id}{voluntary}{count} = 0;
	#	}
	#	if (($flags | H2F_FLAG_VOLUNTARY_MASK) == 0x00) { # Status result of senders request.
	#	    $stats{$id}{requested}{count} += 1;
	#	    $stats{$id}{requested}{No} = $stats{$id}{requested}{count};
	#	    $stats{$id}{requested}{No}{number_holes_sent} = $number_holes_sent;
	#	    push (@{$stats{$id}{requested}{No}{hole_list}}, @sent_hole_list);
	#	}
	#	else { # Status is being voluntarily sent.
	#	    $stats{$id}{voluntary}{count} += 1;
	#	    $stats{$id}{voluntary}{No} = $stats{$id}{voluntary}{count};
	#	    $stats{$id}{voluntary}{No}{progress_indicator} = $progress_indicator;
	#	    $stats{$id}{voluntary}{No}{number_holes_sent} = $number_holes_sent;
	#	    push (@{$stats{$id}{voluntary}{No}{hole_list}}, @sent_hole_list);
	#	}
	#    }
	    $r{in_addr} = $peer_in_addr;
	    $r{id} = $id;
	    return \%r;
	}, #########   End of send STATUS packet!   ############################################################

	###### Rcvd STATUS packet.   ###########################################################################
	rcv => sub {  # ++++ SERVER/Client FUNCTION ++++

	    my ($packet, $peer_in_addr) = @_;
	    my ($voluntary_packet, $complete_hole_list) = ( 0, 0 ) ;
	    my ($s, $usec) = gettimeofday();
	    my $timestamp_nonce_reply;
	    my @desc_format = ('n', 'N', 'q>', 'w'); # lookup table for 'pack' format types.
	    my ($flags, $id, $rest) = unpack "N N a*", $packet;

	    printf "Rcvd Status - Time %0.6d, Flags = %08x, Id = %08x, size of rest = %d \n",
		$usec, $flags, $id, length $rest if $verbose_stat;

	    if (!( (defined $snd_transactions{$id} && defined $snd_transactions{$id}{descriptor}) 	||
		    (defined $rcv_transactions{$id} && defined $rcv_transactions{$id}{action}) )) 	   {
		# Transaction has completed, deleted, or never was, so ignore.
		# $snd_transaction - Status packet from rcvr side of file transfer.
		# $rcv_transaction - Status packet from delete confirmation or error from sndr side of file xfer
		printf STDERR "\n\n Received Status Packet for transaction that does not exist!\n";
		return;
	    }
	    $flags = $flags & 0x00ffffff;

	    my $status = $flags & H2F_FLAG_STATUS_MASK ;

	    if ($status != 0x00) { # Error received or file transfer is complete.
		process_status_message($status, $id);
		return;
	    }

	    if (($flags & H2F_FLAG_TIMESTAMP_MASK) == H2F_FLAG_TIMESTAMP_MASK) {
		# bit 12 = 1, Timestamp/nonce exists.
		($timestamp_nonce_reply, $rest) = unpack 'N[4] a*', $rest;
		# TODO - Need todo something with timestamp.
		#      - Hash entry {timestamp_nonce_reply} may not be needed.
		printf "Rcvd Status - Timestamp set! \n Flags = %08x\n Mask  = %08x\n", $flags,
								    H2F_FLAG_TIMESTAMP_MASK if $verbose_stat;
	    }
	    my $desc_flags = (($flags >> 22) & 3); # move bits 8 & 9, to lsb and mask.
	    my $desc = $desc_format[$desc_flags]; # set $desc = to a pack templete char.
	    (my $progress_indicator, my $in_response_to, $rest) = unpack "$desc $desc a*", $rest;

	    if (defined ($rcv_transactions{$id}) && defined ($rcv_transactions{$id}{action})) { # Id is a rcv.
		if ((($rcv_transactions{$id}{action} eq 'get')
				|| ($rcv_transactions{$id}{action} eq 'getdir')	) &&
		   ($in_response_to == 0					) &&
		   (length $rest <=0 						)) {
		    # Checking for status acceptance packet. Sent to the Rcvr with status and in-response-to
		    # fields set to 0.
		    $rcv_transactions{$id}{status_acceptance_rcvd} = 1; # Nothing done with this yet!
		    printf "Rcvd Status - Acceptance packet rcvd. \n", if $verbose_stat;
		    print STDERR $prompt;
		    return;
		}
		if ($rcv_transactions{$id}{action} eq 'delete')   {
		    printf "Confirmation from peer for deletion of file %s.\n",$rcv_transactions{$id}{del_file};
		    print STDERR $prompt;
		    delete $rcv_transactions{$id};
		    return;
		}
	    }
	    # Status packet is not for a Rcv Transaction, so must be a Snd Transaction. Store indicators.
	    $snd_transactions{$id}{progress_indicator} = $progress_indicator;
	    $snd_transactions{$id}{in_response_to} = $in_response_to;

	    printf "Rcvd Status - Descriptor set to %08x. \n", $snd_transactions{$id}{descriptor}
											    if $verbose_stat;
	    if (($flags & FLAG_DESC_BITS) != $snd_transactions{$id}{descriptor}){
		printf STDERR "Descriptor field is wrong size!" if $verbose_mode;
		# TODO - need to do something with this error!
		printf "Rcvd Status - Desc set to: %08x.  \n", $flags & FLAG_DESC_BITS, if $verbose_stat;
	    }

	    #if (($flags & H2F_FLAG_TIMESTAMP_MASK) == H2F_FLAG_TIMESTAMP_MASK) {
		## bit 12 = 1, Timestamp/nonce exists.
		#($snd_transactions{$id}{timestamp_nonce_reply}, $rest) = unpack 'N[4] a*', $rest;
		## TODO - Need todo something with timestamp.
		##      - Hash entry {timestamp_nonce_reply} may not be needed.
		#printf "Rcvd Status - Timestamp set! \n Flags = %08x\n Mask  = %08x\n", $flags,
								    #H2F_FLAG_TIMESTAMP_MASK if $verbose_stat;
	    #}

	    if (($flags & H2F_FLAG_META_RCVD_MASK) == H2F_FLAG_META_RCVD_MASK) {
		# Bit 13 = 1, Metadata not received. resend it.
		enqueue_at_front($snd_packet{metadata}($id, $peer_in_addr));
		printf "Rcvd Status - Send Metadata! \n", if $verbose_stat;

	    }

	    if (($flags & H2F_FLAG_FULL_HOLELIST_MASK) == H2F_FLAG_FULL_HOLELIST_MASK) {
		# Bit 14 = 1, Incomplete list of holes contained in packet.
		;
		# TODO	- something!
		#     	- Why do we care about a complete holelist?
		#	- Why not just process holelists as packets arrive?
		printf "Rcvd Status - incomplete list of holes! \n", if $verbose_stat;

	    }

	    if (($flags & H2F_FLAG_VOLUNTARY_MASK) == H2F_FLAG_VOLUNTARY_MASK) {
		# Bit 15 =1, This packet was sent vountarily.

		# TODO - something?
		#      - affects contents of the timestamp/nonce field.
		printf "Rcvd Status - Status sent voluntarily! \n", if $verbose_stat;
	    }

	    my $i = $snd_transactions{$id}{desc_no_bits} / 16 ;

	    printf " Length of rest = %d, Masked flags = %08x, Voluntary flag = %08x, data length = %d.\n",
				    length $rest, ($flags & H2F_XFER_COMPLETE_MASK), H2F_FLAG_VOLUNTARY_MASK,
								$snd_transactions{$id}{length} if $verbose_stat;
	    # Check if status packet is indicating that the xfer is completed.
	    # Hole pair list is empty.
	    # bit 14 = 0, indicates complete list of holes.
	    # bit 15 = 1, indicates packet was sent voluntarily.
	    # In_Responce_To is set to end of file.
	    if ((length $rest <= 0)   									&&
		($flags & H2F_XFER_COMPLETE_MASK) == H2F_FLAG_VOLUNTARY_MASK 				&&
		$snd_transactions{$id}{in_response_to} == $snd_transactions{$id}{length}		)
		{
		delete $snd_transactions{$id};
		printf "Rcvd Status - Sending of Transaction Id %08x completed! \n", $id if $verbose_stat;
		return ;
	    } # End IF status packet indicates Transaction has been completed!
	    # IF transaction is not completed then fill holes.
	    printf "Rcvd Status - Desc format = %08x,  Prog Ind = %d. \n", $flags & FLAG_DESC_BITS,
		    $snd_transactions{$id}{progress_indicator} if $verbose_stat;

	    printf "Rcvd Status - Response_to set to: %d. Length of rest = %d  \n",
		$snd_transactions{$id}{in_response_to}, length $rest if $verbose_stat;

	    my $no_hole_pairs = (length $rest)/(2*($snd_transactions{$id}{desc_no_bits} / 8));
	    #  Equals: (size of $rest) divided by (2 times the # of 8 bit bytes in the descriptor size).

	    printf "Rcvd Status - Process Holes list if it exists, # hole pairs = %d! \n", $no_hole_pairs
											    if $verbose_stat;
	    my ($start, $finish);
	    # Get holes, Check if hole is already in queue to be sent, if not add hole to queue.
	    while ($no_hole_pairs) { # Until $no_hole_pairs is zero,
		#locate the missing data and re-enqueue it (at the front)

		($start, $finish, $rest) = unpack "$desc $desc a*", $rest;
		$no_hole_pairs = --$no_hole_pairs;

		printf "Rcvd Status - Processing Hole List! Hole Start = %d, Hole End = %d.\n", $start,
										       $finish if $verbose_stat;
		printf "     elements in queue now = %d, # hole pairs remaining = %d.\n", $#queue + 1,
									 (length $rest)/(4*$i) if $verbose_stat;

		# Check that new offset is still inside the hole request. ie $start and $finish.
		for (my $offset = $start; $offset < $finish; $offset += $data_payload_size) {
		    printf "Rcvd Status - Time: %d, Offset: %x, Finish: %x.\n",
								gettimeofday, $offset, $finish if $verbose_stat;
		    my @P = @queue; # @P - copy of array of hash tables describing packets to be sent.
		    my $h =(); # $h - set to the starting offset # of data packet from queue.
		    my $p =(); # $p - hash table entry from @P.
		    my $packet_exists = 0;

		    # Check if packet already exists in the queue
		    while (@P) { # until @P is empty
			$p = shift @P;
			if (defined $p->{offset}){
			    $h = $p->{offset}; # $h is assigned the offset value of the packet.

			    printf "Hole offset = %d, packet offset =%d \n", $offset, $h
				if ($verbose_stat && $verbose_mode);

			    # If the holes' offset equals the one being checked.
			    if ($offset eq $h) {
				$packet_exists =1;
				printf "Hole packet %x, exists!\n",$offset if $verbose_stat;
			    }
			}
		    }
		    # if packet exists in queue do not requeue.
		    if (!$packet_exists) { # Packet was sent so must have been lost, so requeue.
			my $flags = $snd_transactions{$id}{root_data_flags};

			if (($offset + $data_payload_size) >= length $snd_transactions{$id}{data}){
			    # This is the last packet of the file transfer. Add End Of Data flag (EOD)!
			    $flags = $flags | DATA_EOD;
			}

			enqueue_at_front($snd_packet{data}($flags, $id, $offset,
			    substr($snd_transactions{$id}{data}, $offset, $data_payload_size),
			    $peer_in_addr, my $no_packets = 0));
			send_packet; # send a packet after every check just to keep receiver's timers active.
			#printf "Rcvd Status - NEW Data Packet sent! \n", if $verbose_stat;

		    } # End IF not $packet_exists!
		    # send_packet; # might be redundant.
		} # End for my $offset!
	    } # End of while hole pairs!
	    $snd_transactions{$id}{inactivity_timeout} = gettimeofday + SND_INACTIVITY_TIMEOUT;
	    printf "Rcvd Status - Subroutine executed, Now Exiting! \n", if $verbose_stat;
	}, #### End of rcvd STATUS packet!
    }, #### End of STATUS key hash entry!
);
################################# End of Packet Type Hash table. ###############################################

while (my ($k, $v) = each %by_id) { # creates subroutines from %by_id hash table.
    # warn "key $k, v $v";
    $snd_packet{$v->{name}} = $v->{snd};
    $rcv_packet{$k} = $v->{rcv};
}

#################################   Command Line Hash table.   #################################################
sub no_op_commandline_bookmark {	} # just for a flag to be used with geany.

my %handle_cmd;
%handle_cmd = (

    bye => sub {
	exit 0;
    },

    close => sub { # close the current session
	my ($sfo, $opts) = @_;
	undef $server_in_addr;
    },

    del  => sub {
	return $handle_cmd{delete}(@_);
    },

    delete => sub { # delete the given file on the remote host
	my ($sfo, $file_name) = @_;
	if (!defined $server_in_addr) {
	    print STDERR "? not connected\n";
	    return;
	}
	my $id = calculate_crc32($file_name);
	if (defined $file_name) {
	    $rcv_transactions{$id}{action} = 'delete';
	    $rcv_transactions{$id}{in_addr} = $server_in_addr;
	    $rcv_transactions{$id}{del_file} = $file_name;
	    $rcv_transactions{$id}{time} = time;
	    enqueue_at_back($snd_packet{request}($my_ip_addr, $id, $file_name, $server_in_addr));
	}
	else {
	    warn "?no file specified";
	}
    },

    dir => sub {
	my ($sfo, $dir_name) = @_;
	if (!defined $server_in_addr) {
	    print STDERR "? not connected\n";
	    return;
	}
	if (!defined $dir_name) { # If directory not specified, set to default "./"
	    $dir_name = './';
	}

	my $id = calculate_crc32($dir_name);

	if (defined $rcv_transactions{$id}) {
	    warn "?ignored, directory list currently being requested";
	}
	else {
	    $rcv_transactions{$id}{action} = 'getdir';
	    $rcv_transactions{$id}{in_addr} = $server_in_addr;
	    $rcv_transactions{$id}{get_filename} = $dir_name;
	    $rcv_transactions{$id}{is_directory_list} = 1;
	    $rcv_transactions{$id}{time} = time;
	    warn "submitting 'getdir' packet" if $verbose_gd;
	    enqueue_at_back($snd_packet{request}($my_ip_addr, $id, $dir_name, $server_in_addr));
	}
    },

    disconnect => sub {
	return $handle_cmd{close}(@_);
    },

    dump => sub {
	    $Data::Dumper::Varname = "Receive";
	    printf Dumper(\%{rcv_transactions});
	    $Data::Dumper::Varname = "Send";
	    printf Dumper(\%snd_transactions);
	    printf "\n\n";
    },

    exit => sub {
	return $handle_cmd{bye}(@_);
    },

    get => sub { # get the given file from the remote host
	my ($sfo, $remote_filename, $local_filename) = @_;
	if (!defined $server_in_addr) {
	    print STDERR "? not connected\n";
	    return;
	}
	if (!defined $local_filename) {
	    $local_filename = $remote_filename;
	}
	my $id = calculate_crc32($remote_filename);
	if (defined $rcv_transactions{$id}) {
	    warn "?ignored, file currently being requested";
	}
	else {
	    $rcv_transactions{$id}{action} 		= 'get';
	    $rcv_transactions{$id}{in_addr} 		= $server_in_addr;
	    $rcv_transactions{$id}{get_filename} 	= $remote_filename;
	    $rcv_transactions{$id}{write_filename} 	= $local_filename;
	    $rcv_transactions{$id}{length} 		= 2**MAX_NO_DESC_BITS;
	    $rcv_transactions{$id}{time} 		= time;
	    # $rcv_transactions{$id}{descriptor} 		= MAX_DESC_BITS;
	    $rcv_transactions{$id}{stat_req_cnt} 	= 0;
	    $rcv_transactions{$id}{stat_req_hole_cnt} 	= 0;
	    $rcv_transactions{$id}{stat_vol_cnt} 	= 0;
	    $rcv_transactions{$id}{stat_vol_hole_cnt} 	= 0;
	    enqueue_at_back($snd_packet{request}($my_ip_addr, $id, $remote_filename, $server_in_addr));
	}
    },

    lcd => sub {
	my ($sfo, $dir) = @_;
	chdir($dir) || warn "chdir failed, $!, $dir";
    },

    kill => sub { # 'kill [rcv/snd] [# from list command]
	my ($sfo, $trans_type, $id) = @_;
	printf "Kill cmd - Transaction type: %s, Id# %08x.\n", $trans_type, $id if $verbose_mode;
	if ($trans_type eq 'rcv') {
	    if (exists $rcv_transactions{$id}) {
		delete $rcv_transactions{$id};
		printf " Received Transaction Id #%x has been deleted. \n", $id;
	    }
	    else {
		printf " Received Transaction Id #%x is not an active transaction. \n", $id;
	    }
	}
	elsif ($trans_type eq 'snd') {
		if (exists $snd_transactions{$id}) {
		    delete $rcv_transactions{$id};
		    printf " Sending Transaction Id #%x has been deleted. \n", $id;
		}
		else {
		    printf " Sending Transaction Id #%x is not an active transaction. \n", $id;
		}
	    }
	    else {
		printf " Syntax is wrong, use: 'kill [rcv|snd] Id#'. \n";
	    }
    },


    list => sub {
	for my $id (keys %rcv_transactions) {
	    printf " Received Transaction Id #%x is still active. \n", $id;
	}
	for my $id (keys %snd_transactions) {
	    printf " Sending Transaction Id #%x is still active. \n", $id;
	}
    },

    ls => sub {
	return $handle_cmd{dir}(@_);
    },

    open => sub {
	my ($sfo, $server_hostname) = @_;
	my $ip_addr = gethostbyname($server_hostname);
	if (defined $ip_addr) {
	    syslog LOG_DEBUG, "info: will connect to %s\n", inet_ntoa($ip_addr);
	    $server_in_addr = pack_sockaddr_in($saratoga_port, $ip_addr);
	}
	else {
	    warn "error: can't resolve name $server_hostname";
	}
    },

    peer => sub {
	    $Data::Dumper::Varname = "Peers";
	    printf Dumper(\%peers);
	    printf "\n\n";
    },

    prog => sub {
	return $handle_cmd{progress}(@_);
    },

    progress => sub {
	for my $id (keys %rcv_transactions) { # For every transaction do!
	    if(defined($rcv_transactions{$id}{write_filename})) {
		my $prog = percent_complete(@{$rcv_transactions{$id}{holes}}, $id);
		printf STDERR "%.1f percent of %.2f Kbytes is reported from the %08x transfer of %s.\n",
			    $prog, $rcv_transactions{$id}{length}, $id, $rcv_transactions{$id}{write_filename};
	    }
	}
    },

    put => sub { # put the given file from the remote host
	my ($sfo, $local_filename) = @_;
	if (!defined $server_in_addr) {
	    print STDERR "? not connected\n";
	    return;
	}
	if (! -f $local_filename) { # If local file does not exist then abort.
	    printf "ignored?, file '%s' does not exist!\n", $local_filename;
	    return;
	}
	my $id = calculate_crc32($local_filename);

	if (defined $snd_transactions{$id}) {
	    warn "?ignored, file currently being sent\n";
	}
	else {
	    $snd_transactions{$id}{action} = 'get'; # A 'put' is same as 'get' without the request.
	    $snd_transactions{$id}{in_addr} = $server_in_addr;
	    $snd_transactions{$id}{get_filename} = $local_filename;
	    enqueue_at_front($snd_packet{metadata}($id, $server_in_addr));
	    get_file($server_in_addr, $id, $snd_transactions{$id}{get_filename}) ;
	}
    },

#    pwd => sub {
#	# TODO - report current remote directory
#	my ($sfo, $opts) = @_;
#    },

    quit => sub {
	return $handle_cmd{bye}(@_);
    },

    rate => sub {
	my ($sfo, my $rate) = @_;
	$rate_limit = 0;
	if ($rate > 0) {
	    $rate_limit = 8*($data_payload_size + 52)/($rate * 1000);
	    # 8 bits to a byte * (# bytes in Payload + Header) / (Rate in KB * 1000)
	    printf "Data rate of %.1f Kbps set for this server. \n" , $rate;
	}
	else {
	    printf "Data rate set to line rate for this server. \n" if ($rate == 0);
	}
    },

    recv => sub {
	return $handle_cmd{get}(@_);
    },

    verbose => sub {
	my ($sfo, $opts) = @_;


	if (defined $opts) {

	    SWITCH: {
		if ($opts eq 'off') { #turn debugging off.
		    $verbose_mode	= 0 ;
		    $verbose_rqt	= 0 ;
		    $verbose_meta	= 0 ;
		    $verbose_stat	= 0 ;
		    $verbose_bec 	= 0 ;
		    $verbose_data 	= 0 ;
		    $verbose_iter 	= 0 ;
		    $verbose_dmp	= 0 ; # data dumpers.
		    $verbose_pp		= 0 ; # Place Payload subroutine.
		    $verbose_fh		= 0 ; # First Hole subroutine.
		    $verbose_tc		= 0 ; # Percent Complete subroutine.
		    $verbose_sp		= 0 ; # Send Packet subroutine.
		    $verbose_vs		= 0 ; # Voluntary Status loop in main.
		    $verbose_gd		= 0 ; # Get Directory subroutine.
		    $verbose_pd		= 0 ; # Prt Directory subroutine.
		    $verbose_net	= 0 ; # Get Network Info subroutine.
		    $verbose_rp		= 0 ; # Receive packet subroutine.
		    $verbose_del	= 0 ; # delete file subroutine.
		    $verbose_sum	= 0 ; # Metadata checksum subroutine.
		    $opts = "Turned off!" ;
		    last SWITCH;
		}

		if ($opts eq 'rqt') { #turn debugging on in request subroutine.
		    $verbose_rqt = !$verbose_rqt;
		    $opts = "Request $verbose_rqt" ;
		    last SWITCH;
		}

		if ($opts eq 'meta') { #turn debugging on in sending metadata.
		    $verbose_meta = !$verbose_meta;
		    $opts = "MetaData $verbose_meta" ;
		    last SWITCH;
		}

		if ($opts eq 'stat') { #turn debugging on in sending status.
		    $verbose_stat = !$verbose_stat;
		    $opts = "Status $verbose_stat" ;
		    last SWITCH;
		}

		if ($opts eq 'data') { #turn debugging on in sending data.
		    $verbose_data = !$verbose_data;
		    $opts = "Data $verbose_data" ;
		    last SWITCH;
		}

		if ($opts eq 'iter') { #turn debugging on in iter_holes subroutine.
		    $verbose_iter = !$verbose_iter;
		    $opts = "Iteration $verbose_iter" ;
		    last SWITCH;
		}

		if ($opts eq 'dmp') { #turn dumpper on.
		    $verbose_dmp = !$verbose_dmp;
		    $opts = "Dump $verbose_dmp" ;
		    last SWITCH;
		}

		if ($opts eq 'pp') { #turn debugging on in place_payload.
		    $verbose_pp = !$verbose_pp;
		    $opts = "Place Packet $verbose_pp" ;
		    last SWITCH;
		}

		if ($opts eq 'mode') { #turn general debugging on.
		    $verbose_mode = !$verbose_mode;
		    $opts = "Mode $verbose_mode" ;
		    last SWITCH;
		}

		if ($opts eq 'bec') { #turn debugging on in beacon subroutine.
		    $verbose_bec = !$verbose_bec;
		    $opts = "Beacon $verbose_bec" ;
		    last SWITCH;
		}

		if ($opts eq 'fh') { #turn debugging on in first hole.
		    $verbose_fh = !$verbose_fh;
		    $opts = "First Hole $verbose_fh" ;
		    last SWITCH;
		}

		if ($opts eq 'tc') { #turn debugging on percent complete.
		    $verbose_tc = !$verbose_tc;
		    $opts = "Percent Completed $verbose_tc" ;
		    last SWITCH;
		}

		if ($opts eq 'sp') { #turn debugging on in sending packet.
		    $verbose_sp = !$verbose_sp;
		    $opts = "Data $verbose_sp" ;
		    last SWITCH;
		}

		if ($opts eq 'vs') { #turn debugging on voluntary status.
		    $verbose_vs = !$verbose_vs;
		    $opts = "Iteration $verbose_vs" ;
		    last SWITCH;
		}

		if ($opts eq 'gd') { #turn debugging get_dir.
		    $verbose_gd = !$verbose_gd;
		    $opts = "Dump $verbose_gd" ;
		    last SWITCH;
		}

		if ($opts eq 'gf') { #turn debugging get_dir.
		    $verbose_gf = !$verbose_gf;
		    $opts = "Dump $verbose_gf" ;
		    last SWITCH;
		}

		if ($opts eq 'pd') { #turn debugging on in print dir.
		    $verbose_pd = !$verbose_pd;
		    $opts = "Print dir $verbose_pd" ;
		    last SWITCH;
		}

		if ($opts eq 'net') { # get network info on.
		    $verbose_net = !$verbose_net;
		    $opts = "Mode $verbose_net" ;
		    last SWITCH;
		}
		if ($opts eq 'rp') { # Turn on debugging rcv packet.
		    $verbose_rp = !$verbose_rp;
		    $opts = "Rcv Packet $verbose_rp" ;
		    last SWITCH;
		}

		if ($opts eq 'del') { #turn debugging on in delete file.
		    $verbose_del = !$verbose_del;
		    $opts = "Delete file $verbose_del" ;
		    last SWITCH;
		}

		if ($opts eq 'sum') { # Metadata checksum info on.
		    $verbose_sum = !$verbose_sum;
		    $opts = "Mode $verbose_sum" ;
		    last SWITCH;
		}

		if ($opts eq 'list') { # List debug commands and status '0' = off, '1' = on.
		    printf STDERR "  List of debug commands - Status: '0' = off, '1' = on. \n\n
			     'mode'	General debugging. 					Set to: %d \n
			     'rqt'	Debug sending and receiving of Request packets.		Set to: %d \n
			     'meta'	Debug sending and receiving of MetaData packets.	Set to: %d \n
			     'stat'	Debug sending and receiving of Status packets.		Set to: %d \n
			     'data'	Debug sending and receiving of Data packets.		Set to: %d \n
			     'iter'	Debug of iter_holes subroutine.				Set to: %d \n
			     'dmp'	Turn Dumper commands on or off. (global)		Set to: %d \n
			     'pp'	Debug of place_packet command.				Set to: %d \n
			     'bec'	Beacon debugging. 					Set to: %d \n
			     'fh'	Debug first hole subroutine.				Set to: %d \n
			     'tc'	Debug Percent completed subroutine.			Set to: %d \n
			     'sp'	Debug sending packets subroutine.			Set to: %d \n
			     'vs'	Debug voluntary status packets.				Set to: %d \n
			     'gd'	Debug get dir subroutine.				Set to: %d \n
			     'gf'	Debug get dir subroutine.				Set to: %d \n
			     'pd'	Debug print dir subroutine. 				Set to: %d \n
			     'net'	Debug get network info subroutine.			Set to: %d \n
			     'rp'	Debug receive packet subroutine.			Set to: %d \n
			     'del'	Debug del file subroutine. 				Set to: %d \n
			     'sum'	Debug metadata checksum subroutine.			Set to: %d \n",
			     $verbose_mode, $verbose_rqt, $verbose_meta, $verbose_stat, $verbose_data,
			     $verbose_iter, $verbose_dmp, $verbose_pp, $verbose_bec, $verbose_fh, $verbose_tc,
			     $verbose_sp, $verbose_vs, $verbose_gd, $verbose_gf, $verbose_pd, $verbose_net,
			     $verbose_rp, $verbose_del, $verbose_sum;
		    last SWITCH;
		}

	    }
	}

	printf "verbose mode: %s\n", $opts, if ($opts ne 'list');
    },
);
##################################  End of Hash Table of Commands! #############################################

sub config  {
    if (defined $C_eid) {
    	$eid = $C_eid;
    	printf "Endpoint IDentifier: %s\n", $eid;
    }
    else {
		printf "Default Endpoint IDentifier: %s\n", $eid;
    }
    if (defined $C_hostaddr) {
    	$my_ip_addr = gethostbyname($C_hostaddr);
    	printf "Host address: %s\n", $C_hostaddr;
    }
    else {
		$my_ip_addr = gethostbyname("192.168.1.200");
		printf "Default hostname: %s\n", $C_hostaddr;
    }
    if (defined $C_peeraddr) {
    	$handle_cmd{open}(undef, $C_peeraddr);
    	printf "Peer address: %s\n", $C_peeraddr;
    }
    if (defined $C_verbose) {
    	$verbose_mode = $C_verbose;
    	printf "verbose mode: %d\n", $verbose_mode;
    }
    if (defined $C_rate) {
	    $handle_cmd{rate}(undef, $C_rate);
	    printf "Server's data rate set to %.1f Kbps.\n", $C_rate;
    }
}

# START initalizing varibles +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
if (-f "sara.conf") { # execute configuration file if it exists
    eval `cat sara.conf`;
    config;
}
else {
     printf STDERR "info: sara.conf file does not exist!\n";
}
get_network_info;

if (@ARGV) { # Open connection to peer if peer's address was given on command line
    $handle_cmd{open}(undef, @ARGV);
}

$sfo_multi = IO::Socket::Multicast->new(LocalPort=>$saratoga_port_multi) or die "Can't create socket: $!";
  # Add a multicast group
    $sfo_multi->mcast_add($saratoga_multicast_addr);
    $sfo_multi->mcast_ttl($ttl_multicast);
    if (defined $C_multicast_interface) { $sfo_multi->mcast_if($C_multicast_interface) };

    if (defined $C_lpa_multicast_intf) { $lpa_multicast_intf = $C_lpa_multicast_intf; }
    printf STDERR " LPA: maddr: %s, mport: %d, mintf: %s.\n",
					$lpa_multicast_addr, $lpa_port, $lpa_multicast_intf, if ($verbose_lpa);
$sfo_lpa = IO::Socket::Multicast->new(LocalPort=>$lpa_port) or die "Can't create LPA socket: $!";
    $sfo_lpa->mcast_add($lpa_multicast_addr, 'eth2');
    $sfo_lpa->mcast_if($lpa_multicast_intf);
    printf STDERR "info: Listening for LPA info @ %s:%s!\n", $lpa_multicast_addr, $lpa_port;

$| = 0;
$sfo = IO::Socket::INET->new
    (LocalPort => $saratoga_port,
     Type => SOCK_DGRAM,
     Broadcast => 1,
     Proto => 'udp',
     );
die "socket failed, $!" if !defined $sfo;

print "setting so_rcvbuf ",  setsockopt($sfo, SOL_SOCKET, SO_RCVBUF, 8192*1000), "\n";
my ($sport, $saddr) = sockaddr_in(getsockname($sfo));
printf STDERR "info: listening at %s:%s\n", inet_ntoa($my_ip_addr), $sport;

vec($rin, fileno(STDIN), 1) = 1;
vec($rin, $sfo->fileno(), 1) = 1;
vec($rin, $sfo_multi->fileno(), 1) = 1;
vec($rin, $sfo_lpa->fileno(), 1) = 1;

my $t0 = gettimeofday;
print STDERR $prompt;

#################################################################################################
for (;;) { # Start main program loop

    select($rout = $rin, $wout = $win, $eout = $ein, $tick_interval);

    if (vec($rout, fileno(STDIN), 1)) { # Check for keyboard entry
	my $cmd_line = <STDIN>; # more properly syssread()
	chomp $cmd_line;
	if (defined($cmd_line) && length $cmd_line) {
	    my ($cmd, $cmd_opts) = split /\s+/, $cmd_line, 2;
	    $cmd = lc $cmd;
	    if (defined $handle_cmd{$cmd}) { # Execute keyboard command
		$handle_cmd{$cmd}($sfo, $cmd_opts);
	    }
	    else {
		print "?Invalid command\n";
	    }
	}
	print STDERR $prompt;
    }

    receive_packet;

    receive_LPA_packet;

    send_packet;

    my $t1 = gettimeofday;
    # syslog LOG_DEBUG, "debug: delta time %g\n", $t1 - $t0;

    #  Receiver Function
    for my $id (keys %rcv_transactions) { # For every received transaction do!
	my @hp;
	if (defined $rcv_transactions{$id}{holes}) {
	    @hp = @{$rcv_transactions{$id}{holes}};
	}
	# {last_packet_rcvd} set to the time that last packet for a transaction was received.
	# {alldone} indicates file has been completely received.
	# RCV_STATUS_PERIOD, timeout timer for receiver to send status if sndr goes quiet.
	if (	defined($rcv_transactions{$id}{last_packet_rcvd}) 			&&
		!exists($rcv_transactions{$id}{alldone}) 				&&
		$#hp >= 0								&&
		$rcv_transactions{$id}{last_packet_rcvd} < ($t1 - RCV_STATUS_PERIOD)
	    ) {
	    $rcv_transactions{$id}{last_packet_rcvd} = $t1; # Timer reset since STATUS packet is being sent.
	    my $flags = $rcv_transactions{$id}{status_flags} | H2F_FLAG_VOLUNTARY_MASK ;
	    if (!defined $rcv_transactions{$id}{metadata}) { # add metadata not received flag.
		$flags = $flags | H2F_FLAG_META_RCVD_MASK;
	    }

	    my $status = 0x000000 ; # status bits set to 0x00, no errors
	    my $progress_indicator = first_hole (@{$rcv_transactions{$id}{holes}}) ;
	    my $in_response_to = 0x00000000 ;

	    printf "Voluntary Status - Flags = %x, Prog. ind. = %d, In resp2 = %d.\n",
						$flags, $progress_indicator, $in_response_to if $verbose_vs;

	    enqueue_at_front($snd_packet{status}($rcv_transactions{$id}{in_addr}, $flags, $status, $id,
				$progress_indicator, $in_response_to, \@{$rcv_transactions{$id}{holes}}), $id);
	} # End  'if' statement

	printf "Main Loop - Time is %0.3d, \n Waiting for metadata = %0.3d,\n Timerset to %0.3d.\n\n",
	    $t1, $rcv_transactions{$id}{waiting_for_metadata}, TIMER_TO_WAIT_FOR_METADATA
		if $verbose_meta && defined $rcv_transactions{$id}{waiting_for_metadata};

	if (defined $rcv_transactions{$id}{waiting_for_metadata} 					&&
			$rcv_transactions{$id}{waiting_for_metadata} < ($t1 - TIMER_TO_WAIT_FOR_METADATA)
	    ){ # Timer waiting for metadata has expired.
	    my $dref = \$rcv_transactions{$id}{data};
	    warn "Notice: Metadata not received, using ID as filename to write.\n";
	    file_complete ($server_in_addr, $dref, $id, $flags);
	    delete $rcv_transactions{$id};
	}
	# If {inactivity_timeout} has expired
	if (exists($rcv_transactions{$id}{inactivity_timeout}) &&
						   $rcv_transactions{$id}{inactivity_timeout} < $t1) {
	    # - give up with this transaction

	    if (exists $rcv_transactions{$id}{alldone}) { # transfer completed!
		printf "notice: Receive transaction Id: %08x complete.\n", $id;
	    }
	    else { # transfer incomplete, but timed out!
		warn "Notice: inactivity timeout, cancelling transaction.\n";
	    }

	    print STDERR "\n$prompt";

	    delete $rcv_transactions{$id};
	}
    } # End FOR every rcv_transaction loop

    #  Sender Function
    for my $id (keys %snd_transactions) { # For every received transaction do!

	# If {inactivity_timeout} has expired
	if (exists($snd_transactions{$id}{inactivity_timeout}) &&
						   $snd_transactions{$id}{inactivity_timeout} < $t1) {
	    # - give up with this transaction
	    warn "Notice: inactivity timeout, cancel sending transaction.\n";

	    print STDERR "\n$prompt";
	    delete $snd_transactions{$id};
	}
	else { # No inactivity timer set for send transaction so set one.
	    $snd_transactions{$id}{inactivity_timeout} = gettimeofday + SND_INACTIVITY_TIMEOUT;
	}
    } # End FOR every snd_transaction loop

    printf "Beacon - Enable beacon is set to %0.2d, T0 = %0.2d, T1 = %d. \n",
						      $enable_beacon, $t0, $t1 if $verbose_mode && $verbose_bec;

    if ($enable_beacon && (($t1 - $t0) >= BEACON_INTERVAL)) {
	printf STDERR "info: sending beacon\n" if $verbose_bec;
	$t0 = time;

	my %r = %{$snd_packet{beacon}()};

	if ($en_beacon_broadcast) {
	    enqueue_at_front(\%r);
	}
	if ($en_beacon_multicast) {
	    $sfo_multi->mcast_send($r{payload}, "$saratoga_multicast_addr:$saratoga_port_multi");
	}

    }
} # End main program loop

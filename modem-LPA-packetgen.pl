#!/usr/bin/env perl
# Modem LPA multicast packet Generator.
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
use Net::IP;
use IO::Socket::INET;
use IO::Socket::Multicast;
use IO::Interface::Simple;
use Sys::Hostname;
use Time::HiRes qw{usleep gettimeofday time};
use Digest::MD5::File qw(dir_md5_hex file_md5_hex url_md5_hex);

use constant 
	{	MODEM_FLAG_SA_BIT 			=> 0x0001,	# Modem Flag, Some or All bit 31 mask.
		
		MODEM_INTF_FLAG_BIDIR_BIT 	=> 0x0020,	# Modem interface Flag, Bidirectional interface, bit 26 mask.
		MODEM_INTF_FLAG_FIX_BIT 	=> 0x0010,	# Modem interface Flag, Fix rate, bit 27 mask.
		MODEM_INTF_FLAG_IPv4_BIT 	=> 0x0008,	# Modem interface Flag, Ipv4 address, bit 28 mask.
		MODEM_INTF_FLAG_IPv6_BIT 	=> 0x0004,	# Modem interface Flag, IPv6 address, bit 29 mask.
		MODEM_INTF_FLAG_UD_BIT 		=> 0x0002,	# Modem interface Flag, interface Up or Down, bit 30 mask.
		MODEM_INTF_FLAG_IO_BIT 		=> 0x0001	# Modem interface Flag, in or out interface, bit 31 mask.
     };

my $rin = ''; # event bits
my $win = '';
my $ein = '';
my ($rout, $wout, $eout);
# The rate in seconds at which the event loop checks for timeout
# events.
my $tick_interval = 0.125;

my $verbose				= 1;
my $one_shot			= 0;
my $continuous			= 0;
my $prompt				= "LPA>";
my $timer				= 1; 		# how often to send LPA packets if continuous is selected.
my $lpa_dst_port 		= 7575;
my $lpa_src_multi 		= 17543;
my $lpa_multicast_addr 	= '226.1.1.2';
my $ttl_multicast 		= 4; 	  # TTL for sent multicast packet.
my $multicast_interface = 'eth3'; # Sets the interface that multicast packets are sent out.

my $block_type_ID 		= 0x0001;
my $block_length 		= 0x0020;
my $no_links 			= 0x01;
my $link_rate_desc_size = 0x01;
my $modem_flags 		= 0x0000;
my $modem_id 			= 0xaaaaaaaa;
my $mtu 				= 1500;
my $interface_flags 	= 0x003A;
my $current_rate 		= 8000000;
my $min_rate			= 128000;
my $max_rate			= 100000000;
my $modem_ipv4_addr		= "192.168.1.1";
my $modem_ipv6_addr;

my %handle_cmd;

%handle_cmd = (

    bye => sub {
	exit 0;
    },
    
    exit => sub {
	return $handle_cmd{bye}(@_);
    },
    
    quit => sub {
	return $handle_cmd{bye}(@_);
    },
    

    block => sub { # change the block ID.
	my ($sfo, $opts) = @_;
	$block_type_ID = $opts;
   },

    continuous => sub { 
	$continuous = !$continuous;
   },
   	
    cont => sub {
	return $handle_cmd{continuous}(@_);
    },
           
    modem => sub { # change the Modem ID.
	my ($sfo, $opts) = @_;
	$modem_id = $opts;
   },	
   
	rate => sub { # change the Current Rate.
	my ($sfo, $opts) = @_;
	$current_rate = $opts;
    },

    send => sub { # change the Modem ID.
	my ($sfo, $opts) = @_;
	$one_shot = 1;
   },
   	
	timer => sub { # change the period of messages sent.
	my ($sfo, $opts) = @_;
	$timer = $opts;
    },
    
    verbose => sub { 
	$verbose = !$verbose;
	printf " Verbose mode is turned %s!\n", my $word = $verbose ? "on" : "off" ;
   },
   	
   
    help => sub { # change the Modem ID.
		printf STDERR "Commands!\n\n";
		printf STDERR "     'bye', 'quit', 'exit'   Exit program! \n";
		printf STDERR "     'block <id>'            Set Block Type ID. \n";
		printf STDERR "     'continuous', 'cont'    Toggles sending LPA packets at intervals set by 'timer' option. \n";
		printf STDERR "     'modem <id>'            Set Modem ID. \n";
		printf STDERR "     'rate <bits/sec>'       Set current link rate in bits ber second. \n";
		printf STDERR "     'send'                  Send one LPA packet. \n";
		printf STDERR "     'timer <seconds>'       Set timer for how often packets are sent out in continuous mode. \n";
		printf STDERR "     'verbose'               Toggle messaging. \n";
		printf STDERR "     'help'                  Print this help screen. \n\n\n";

   },	   
    
);
##################################  End of Hash Table of Commands! #############################################

my $ip = $modem_ipv4_addr;
$ip = new Net::IP($ip)
	or die (Net::IP::Error());
my $modem_ipv4_hex = oct $ip->hexip();

my $sfo; 	# socket file object (IO::Handle)
my $sfo_multi;	# socket file object for multicast (IO::Socket::Multicast)

sub print_field_values { ############################### Print Field Values ! ###################################
	
	my ($q) = @_;		
	
	my ($block_type_ID, $block_length, $link_info, $modem_flags, $modem_id, $mtu, $interface_flags, $current_rate, $min_rate, $max_rate, 
																								$modem_ipv4_hex) = unpack 'n n n n N n n N N N N', $q;	
		
	printf "\n			Modem LPA Packet Field Values Sent.";
	
	printf "\n	
		Block Type		: 0x%04x 
		Block Length		: 0x%04x 
		No. Links | Rate Desc	: 0x%04x 
		Modem Flags		: 0x%04x 
		Modem ID		: 0x%08x 
		MTU			: 0x%04d 
		Intf Flags		: 0x%04x
		Current Rate		: 0x%08d
		Minimum Rate		: 0x%08d
		Maximum Rate		: 0x%0d
		Modem's IPv4 addr	: 0x%08x \n", $block_type_ID, $block_length, $link_info, $modem_flags, $modem_id, $mtu, $interface_flags, 
				$current_rate, $min_rate, $max_rate, $modem_ipv4_hex;
																					
} ############################### End of print field values ! ###################################

sub pack_payload { ############################### pack payload ! ###################################
	# Pack payload to be sent in packet
	printf "Pack Payload - executing!\n", if $verbose;
	
	my ($block_type_ID, $block_length, $no_links, $link_rate_desc_size, $modem_flags, $modem_id, $mtu, $interface_flags, $current_rate,  
																					$min_rate, $max_rate, $modem_ipv4_addr, $modem_ipv6_addr) = @_;

	my $link_info = (( $no_links << 8 )| $link_rate_desc_size );
	
	my $r ;	
	
	$r = pack 'n n n n N n n N N N N', $block_type_ID, $block_length, $link_info, $modem_flags, $modem_id, $mtu, $interface_flags, 
																						$current_rate, 	$min_rate, $max_rate, $modem_ipv4_hex;	
	if ($verbose == 1) { print_field_values ($r) }																														
	return $r;  
																					
} ############################### End of pack_payload ! ###################################

$sfo_multi = IO::Socket::Multicast->new(); 
  # Add a multicast group
  $sfo_multi->mcast_add($lpa_multicast_addr);
  $sfo_multi->mcast_ttl($ttl_multicast);
  if (defined $multicast_interface) { $sfo_multi->mcast_if($multicast_interface) }
	else { printf STDERR "info: multicast inteface NOT defined!\n"}

$|=1;
vec($rin, fileno(STDIN), 1) = 1;
$handle_cmd{help}();
print STDERR $prompt;
##################################################################################################
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
		$handle_cmd{help}();
	    }
	}
	print STDERR $prompt;
    }



 
	if ($one_shot == 1 || $continuous == 1) {
	    $sfo_multi->mcast_send(pack_payload($block_type_ID, $block_length, $no_links, $link_rate_desc_size, $modem_flags, $modem_id, $mtu, 
											$interface_flags, $current_rate, $min_rate, $max_rate, $modem_ipv4_addr, $modem_ipv6_addr), 
																												"$lpa_multicast_addr:$lpa_dst_port");
		printf STDERR "Multicast Packet Sent!\n";
		print STDERR $prompt;
		$one_shot = 0;																										
		sleep $timer;
	}
} # End main program loop

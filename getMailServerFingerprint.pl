#!/usr/bion/perl

use warnings "all";
use strict;

use FindBin;
use File::Spec;
use local::lib File::Spec->catfile($FindBin::Bin,'.plEnv');

use IO::Socket::SSL;

if(scalar(@ARGV)==2) {
	my $cl = IO::Socket::SSL->new(
		PeerAddr => $ARGV[0].":".$ARGV[1], 
		SSL_verify_mode => 0
	);
	print "# Put next line in user-management.ini file\n";
	print "# under [mail] section\n";
	print "ssl_options=SSL_fingerprint=".$cl->get_fingerprint."\n";
} else {
	print STDERR "Usage: $0 {server ip} {server port}\n";
}

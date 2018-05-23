#!/usr/bin/perl

use warnings "all";
use strict;

use Carp;
use Config::IniFiles;

use FindBin;
use lib $FindBin::Bin . '/libs';
use RDConnect::UserManagement;

if(scalar(@ARGV)==2) {
	my $configFile = shift(@ARGV);
	my $username = shift(@ARGV);
	
	# Now, let's read all the parameters
	my $cfg = Config::IniFiles->new( -file => $configFile);
	
	# LDAP configuration
	my $uMgmt = RDConnect::UserManagement->new($cfg);
	
	my($success,$payload) = $uMgmt->generateGDPRHash($username);
	
	if($success) {
		print "Token ===> $payload\n";
		exit 0;
	} else {
		foreach my $err (@{$payload}) {
			Carp::carp($err);
		}
		exit 1;
	}
} else {
	die "Usage: $0 {IniFile} {username or user e-mail}\n";
}

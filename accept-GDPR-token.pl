#!/usr/bin/perl
# RD-Connect User Management Scripts
# José María Fernández (jose.m.fernandez@bsc.es)

use warnings "all";
use strict;

use FindBin;
use File::Spec;
use local::lib File::Spec->catfile($FindBin::Bin,'.plEnv');

use Carp;
use Config::IniFiles;

use lib File::Spec->catfile($FindBin::Bin,'libs');
use RDConnect::UserManagement;

if(scalar(@ARGV)==3) {
	my $configFile = shift(@ARGV);
	my $username = shift(@ARGV);
	my $acceptToken = shift(@ARGV);
	
	# Now, let's read all the parameters
	my $cfg = Config::IniFiles->new( -file => $configFile);
	
	# LDAP configuration
	my $uMgmt = RDConnect::UserManagement->new($cfg);
	
	my($success,$payload) = $uMgmt->acceptGDPRHash($username,$acceptToken);
	
	if($success) {
		print "User $username accepted GDPR\n";
		exit 0;
	} else {
		foreach my $err (@{$payload}) {
			Carp::carp($err);
		}
		exit 1;
	}
} else {
	die "Usage: $0 {IniFile} {username or user e-mail} {GDPR token}\n";
}

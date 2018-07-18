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

my %validEnableValues = (
	'T'	=>	1,
	't'	=>	1,
	'true'	=>	1,
	'TRUE'	=>	1,
	'ON'	=>	1,
	'on'	=>	1,
	'enable'	=>	1,
	'ENABLE'	=>	1,
	'1'	=>	1,
	'F'	=>	undef,
	'f'	=>	undef,
	'false'	=>	undef,
	'FALSE'	=>	undef,
	'OFF'	=>	undef,
	'off'	=>	undef,
	'disable'	=>	undef,
	'DISABLE'	=>	undef,
	'0'	=>	undef,
);

if(scalar(@ARGV)==3) {
	my $configFile = shift(@ARGV);
	my $username = shift(@ARGV);
	my $doEnableState = shift(@ARGV);
	
	# Now, let's read all the parameters
	my $cfg = Config::IniFiles->new( -file => $configFile);
	
	Carp::croak("ERROR: '$doEnableState' is not a valid value")  unless(exists($validEnableValues{$doEnableState}));
	
	# LDAP configuration
	my $uMgmt = RDConnect::UserManagement->new($cfg);
	
	my($success,$payload) = $uMgmt->enableUser($username,$validEnableValues{$doEnableState});
	
	if($success) {
		print "User $username was ".($validEnableValues{$doEnableState} ? 'enabled' : 'disabled')."\n";
		exit 0;
	} else {
		foreach my $err (@{$payload}) {
			Carp::carp($err);
		}
		exit 1;
	}
} else {
	die "Usage: $0 {IniFile} {username or user e-mail} (".join('|',sort { return "\L$a" cmp "\L$b" } keys(%validEnableValues)).")\n";
}

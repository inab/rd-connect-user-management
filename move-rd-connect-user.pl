#!/usr/bin/perl

use warnings "all";
use strict;

use FindBin;
use File::Spec;
use local::lib File::Spec->catfile($FindBin::Bin,'.plEnv');

use Carp;
use Config::IniFiles;
use Email::Address;
use Text::Unidecode qw();

use lib File::Spec->catfile($FindBin::Bin,'libs');
use RDConnect::UserManagement;

use constant SECTION	=>	'main';

if(scalar(@ARGV)>=3) {
	my $configFile = shift(@ARGV);
	
	my $cfg = Config::IniFiles->new( -file => $configFile);
	
	my($username,$organizationalUnitName) = @ARGV;
	
	# LDAP configuration
	my $uMgmt = RDConnect::UserManagement->new($cfg);
	
	# Change the group name
	my($success,$payload) = $uMgmt->moveUserToPeopleOU($username,$organizationalUnitName);
	
	if($success) {
		print "User $username is now on organizational unit $organizationalUnitName\n";
	} else {
		foreach my $retval (@{$payload}) {
			Carp::carp($retval);
		}
	}
} else {
	die <<EOF ;
Usage:	$0 {IniFile} {username or e-mail} {destination organizational unit}
EOF
}

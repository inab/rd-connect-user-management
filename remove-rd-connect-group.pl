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

if(scalar(@ARGV)==2) {
	my $configFile = shift(@ARGV);
	
	my $cfg = Config::IniFiles->new( -file => $configFile);
	
	my($groupName) = @ARGV;
	
	# LDAP configuration
	my $uMgmt = RDConnect::UserManagement->new($cfg);
	
	# Change the group name
	my($success,$payload) = $uMgmt->removeGroup($groupName);
	
	if($success) {
		print "Group $groupName has been removed\n";
	} else {
		foreach my $retval (@{$payload}) {
			Carp::carp($retval);
		}
	}
} else {
	die <<EOF ;
Usage:	$0 {IniFile} {group name}
EOF
}

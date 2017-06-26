#!/usr/bin/perl

use warnings "all";
use strict;

use Carp;
use Config::IniFiles;
use Email::Address;
use Text::Unidecode qw();

use FindBin;
use lib $FindBin::Bin . '/libs';
use RDConnect::UserManagement;

use constant SECTION	=>	'main';

if(scalar(@ARGV)>=3) {
	my $configFile = shift(@ARGV);
	
	my $cfg = Config::IniFiles->new( -file => $configFile);
	
	my($oldGroupName,$newGroupName) = @ARGV;
	
	# LDAP configuration
	my $uMgmt = RDConnect::UserManagement->new($cfg);
	
	# Change the group name
	my($success,$payload) = $uMgmt->renameGroup($oldGroupName,$newGroupName);
	
	if($success) {
		print "Group $oldGroupName is now $newGroupName\n";
	} else {
		foreach my $retval (@{$payload}) {
			Carp::carp($retval);
		}
	}
} else {
	die <<EOF ;
Usage:	$0 {IniFile} {old group name} {new group name}
EOF
}

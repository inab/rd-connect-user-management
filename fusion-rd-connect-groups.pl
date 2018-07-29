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
use Email::Address;
use Text::Unidecode qw();

use lib File::Spec->catfile($FindBin::Bin,'libs');
use RDConnect::UserManagement;

use constant SECTION	=>	'main';

if(scalar(@ARGV)>=3) {
	my $configFile = shift(@ARGV);
	
	my $cfg = Config::IniFiles->new( -file => $configFile);
	
	my($oldGroupName,$newGroupName) = @ARGV;
	
	# LDAP configuration
	my $uMgmt = RDConnect::UserManagement->new($cfg);
	
	# Change the group name
	my($success,$payload) = $uMgmt->moveGroupMembers($oldGroupName,$newGroupName);
	
	if($success) {
		print "Group members from $oldGroupName are now inside $newGroupName\n";
	} else {
		foreach my $retval (@{$payload}) {
			Carp::carp($retval);
		}
	}
} else {
	die <<EOF ;
Usage:	$0 {IniFile} {old group name} {fusionated group name}
EOF
}

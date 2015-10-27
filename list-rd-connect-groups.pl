#!/usr/bin/perl

use warnings "all";
use strict;

use Carp;
use Config::IniFiles;

use FindBin;
use lib $FindBin::Bin . '/libs';
use RDConnect::UserManagement;


if(scalar(@ARGV)==1) {
	my $configFile = shift(@ARGV);
	
	# Now, let's read all the parameters
	my $cfg = Config::IniFiles->new( -file => $configFile);
	
	# LDAP configuration
	my $uMgmt = RDConnect::UserManagement->new($cfg);
	
	my @groups = $uMgmt->listGroups();
	
	if(scalar(@groups)>0) {
		print "# Available groups (and the owner and members)\n";
		foreach my $entry (@groups) {
			print join("\t",$entry->get_value('cn'),$entry->dn(),$entry->get_value('description'),$entry->get_value('owner'),$entry->get_value('member')),"\n";
		}
	}
} else {
	die "Usage: $0 {IniFile}";
}

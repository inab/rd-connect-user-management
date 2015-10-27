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
	
	my @peopleOUs = $uMgmt->listPeopleOU();
	
	if(scalar(@peopleOUs)>0) {
		print "# Available people OUs\n";
		foreach my $entry (@peopleOUs) {
			print join("\t",$entry->get_value('ou'),$entry->dn(),$entry->get_value('description')),"\n";
		}
	}
} else {
	die "Usage: $0 {IniFile}";
}

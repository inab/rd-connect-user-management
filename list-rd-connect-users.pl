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
	
	my @users = $uMgmt->listUsers();
	
	if(scalar(@users)>0) {
		print "# Available users\n";
		print "# ",join("\t",'uid','Is enabled?','user DN','user CN','Given name','Surname(s)','e-mail(s)'),"\n";
		foreach my $entry (@users) {
			print join("\t",$entry->get_value('uid'),($entry->get_value('disabledAccount') eq 'TRUE')?'DISABLED':'ENABLED',$entry->dn(),$entry->get_value('cn'),$entry->get_value('givenName'),join(' ',$entry->get_value('sn')),join(';',$entry->get_value('mail'))),"\n";
		}
	}
} else {
	die "Usage: $0 {IniFile}";
}

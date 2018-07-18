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


if(scalar(@ARGV)==1) {
	my $configFile = shift(@ARGV);
	
	# Now, let's read all the parameters
	my $cfg = Config::IniFiles->new( -file => $configFile);
	
	# LDAP configuration
	my $uMgmt = RDConnect::UserManagement->new($cfg);
	
	my @users = $uMgmt->listUsers();
	
	my($success,$payload) = $uMgmt->listUsers();
	unless($success) {
		foreach my $err (@{$payload}) {
			Carp::carp($err);
		}
		
		exit 1;
	}
	if(scalar(@{$payload})>0) {
		print "# Available users\n";
		print "# ",join("\t",'uid','Is enabled?','user DN','user CN','Given name','Surname(s)','e-mail(s)'),"\n";
		foreach my $entry (@{$payload}) {
			print join("\t",$entry->get_value('uid'),($entry->get_value('disabledAccount') eq 'TRUE')?'DISABLED':'ENABLED',$entry->dn(),$entry->get_value('cn'),$entry->get_value('givenName'),join(' ',$entry->get_value('sn')),join(';',$entry->get_value('mail'))),"\n";
		}
	}
} else {
	die "Usage: $0 {IniFile}";
}

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
	
	my($success,$payload) = $uMgmt->listPeopleOU();
	
	if($success) {
		print "# Available people OUs\n";
		print "# ",join("\t",'Organizational Unit','dn','description'),"\n";
		foreach my $entry (@{$payload}) {
			print join("\t",$entry->get_value('ou'),$entry->dn(),$entry->get_value('description')),"\n";
		}
	} else {
		foreach my $err (@{$payload}) {
			Carp::carp($err);
		}
		exit 1;
	}
} else {
	die "Usage: $0 {IniFile}";
}

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
	
	my($success,$payload) = $uMgmt->listGroups();
	
	if($success) {
		print "# Available roles / groups (and the owner and members)\n";
		print "# ",join("\t",'role / group CN','role / group DN','description','owner(s)','members'),"\n";
		foreach my $entry (@{$payload}) {
			print join("\t",$entry->get_value('cn'),$entry->dn(),$entry->get_value('description'),join(';',$entry->get_value('owner')),join(';',$entry->get_value('member'))),"\n";
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

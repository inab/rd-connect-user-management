#!/usr/bin/perl

use warnings "all";
use strict;

use Carp;
use Config::IniFiles;

use FindBin;
use lib $FindBin::Bin . '/libs';
use RDConnect::UserManagement;

use constant SECTION	=>	'main';

my $doReplace;
if(scalar(@ARGV)>0 && $ARGV[0] eq '-r') {
	shift(@ARGV);
	$doReplace = 1;
}

if(scalar(@ARGV)==2) {
	my $configFile = shift(@ARGV);
	my $groupsFile = shift(@ARGV);
	
	# Now, let's read all the parameters
	my $cfg = Config::IniFiles->new( -file => $configFile);
	
	# LDAP configuration
	my $uMgmt = RDConnect::UserManagement->new($cfg);
	
	# Read the groups
	if(open(my $G,'<:encoding(UTF-8)',$groupsFile)) {
		while(my $line=<$G>) {
			# Skipping comments
			next  if(substr($line,0,1) eq '#');
			
			chomp($line);
			my($shortname,$description,$ownerUID,$junk) = split(/\t/,$line,4);
			
			if(defined($ownerUID) && length($ownerUID) > 0) {
				Carp::croak("Unable to create group $shortname")  unless($uMgmt->createGroup($shortname,$description,$ownerUID,undef,undef,$doReplace));
			} else {
				Carp::croak("Unable to create organizational unit $shortname")  unless($uMgmt->createPeopleOU($shortname,$description,undef,$doReplace));
			}
		}
		
		close($G);
	} else {
		Carp::croak("Unable to read file $groupsFile");
	}
} else {
	die "Usage: $0 [-r] {IniFile} {Tabular file with new groups or organizational units (in UTF-8)}";
}

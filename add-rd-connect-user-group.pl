#!/usr/bin/perl

use warnings "all";
use strict;

use Carp;
use Config::IniFiles;

use FindBin;
use lib $FindBin::Bin . '/libs';
use RDConnect::UserManagement;

use constant SECTION	=>	'main';

if(scalar(@ARGV)==2) {
	my $configFile = shift(@ARGV);
	my $userGroupsFile = shift(@ARGV);
	
	# Now, let's read all the parameters
	my $cfg = Config::IniFiles->new( -file => $configFile);
	
	# LDAP configuration
	my $uMgmt = RDConnect::UserManagement->new($cfg);
	
	# Read the user <-> groups
	if(open(my $UG,'<:encoding(UTF-8)',$userGroupsFile)) {
		while(my $line=<$UG>) {
			chomp($line);
			my($userUID,$groupCN,$junk) = split(/\t/,$line,3);
			
			Carp::croak("Unable to associate user $userUID to group $groupCN")  unless($uMgmt->addUserToGroup($userUID,$groupCN));
		}
		
		close($UG);
	} else {
		Carp::croak("Unable to read file $userGroupsFile");
	}
} else {
	die "Usage: $0 {IniFile} {Tabular file with user <-> group correspondence}";
}

#!/usr/bin/perl

use warnings "all";
use strict;

use Carp;
use Config::IniFiles;

use FindBin;
use lib $FindBin::Bin . '/libs';
use RDConnect::UserManagement;

use constant SECTION	=>	'main';

if(scalar(@ARGV)>=2) {
	my $configFile = shift(@ARGV);
	
	# Now, let's read all the parameters
	my $cfg = Config::IniFiles->new( -file => $configFile);
	
	# LDAP configuration
	my $uMgmt = RDConnect::UserManagement->new($cfg);
	
	foreach my $userGroupsFile (@ARGV) {
		# Read the user <-> groups
		if(open(my $UG,'<:encoding(UTF-8)',$userGroupsFile)) {
			while(my $line=<$UG>) {
				# Skipping comments
				next  if(substr($line,0,1) eq '#');
				
				chomp($line);
				my($userUID,$groupCN,$altUserUID,$altGroupCN,$junk) = split(/\t/,$line,5);
				
				if(defined($altGroupCN) && length($altGroupCN) > 0) {
					$userUID = $altUserUID;
					
					my $firstComma = index($altGroupCN,',');
					$groupCN = ($firstComma == -1) ? $altGroupCN : substr($altGroupCN,$firstComma+1);
				}
				
				my @groupCNs = split(/,/,$groupCN);
				
				Carp::croak("Unable to associate user $userUID to group(s) $groupCN")  unless($uMgmt->addUserToGroup($userUID,\@groupCNs));
				
				print "$userUID => $groupCN\n";
			}
			
			close($UG);
		} else {
			Carp::croak("Unable to read file $userGroupsFile");
		}
	}
} else {
	die "Usage: $0 {IniFile} {Tabular file with user <-> group correspondence}+";
}

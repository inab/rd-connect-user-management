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

use constant SECTION	=>	'main';

my $doReplace;
if(scalar(@ARGV)>0 && $ARGV[0] eq '-r') {
	shift(@ARGV);
	$doReplace = 1;
}

my $skipOU;
if(scalar(@ARGV)>0 && $ARGV[0] eq '-s') {
	shift(@ARGV);
	$skipOU = 1;
}

my $skipGroupOfNames;
if(scalar(@ARGV)>0 && $ARGV[0] eq '-S') {
	shift(@ARGV);
	$skipGroupOfNames = 1;
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
			my($shortname,$description,$ownerUIDList,$alsoOU,$junk) = split(/\t/,$line,5);
			
			unless($skipOU) {
				if(!defined($ownerUIDList) || length($ownerUIDList) == 0 || (defined($alsoOU) && length($alsoOU) > 0 && $alsoOU)) {
					Carp::croak("Unable to create organizational unit $shortname")  unless($uMgmt->createPeopleOU($shortname,$description,undef,$doReplace));
				}
			}
			
			unless($skipGroupOfNames) {
				if(defined($ownerUIDList) && length($ownerUIDList) > 0) {
					my @ownerUIDs = split(/,/,$ownerUIDList);
					Carp::croak("Unable to create group $shortname")  unless($uMgmt->createGroup($shortname,$description,\@ownerUIDs,undef,undef,$doReplace));
				}
			}
		}
		
		close($G);
	} else {
		Carp::croak("Unable to read file $groupsFile");
	}
} else {
	die "Usage: $0 [-r] [-s] [-S] {IniFile} {Tabular file with new groups or organizational units (in UTF-8)}";
}

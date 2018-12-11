#!/usr/bin/perl
# RD-Connect User Management Scripts
# José María Fernández (jose.m.fernandez@bsc.es)

use strict;
use warnings "all";

use FindBin;
use File::Spec;
use local::lib File::Spec->catfile($FindBin::Bin,'.plEnv');

use Carp;
use Config::IniFiles;

use lib File::Spec->catfile($FindBin::Bin,'libs');
use RDConnect::UserManagement;

use constant SECTION	=>	'main';

if(scalar(@ARGV)==2) {
	my $configFile = shift(@ARGV);
	my $ouPairsFile = shift(@ARGV);
	
	# Now, let's read all the parameters
	my $cfg = Config::IniFiles->new( -file => $configFile);
	
	# LDAP configuration
	my $uMgmt = RDConnect::UserManagement->new($cfg);
	
	# Read the pairs
	if(open(my $OUP,'<:encoding(UTF-8)',$ouPairsFile)) {
		while(my $line=<$OUP>) {
			# Skipping comment lines
			next  if(substr($line,0,1) eq '#');
			
			chomp($line);
			my($oldOUname,$newOUname) = split(/\t/,$line);
			
			# First, check whether the destination OU exists, skipping its creation in that case
			my($existsNewOU) = $uMgmt->getPeopleOU($newOUname);
			if($existsNewOU) {
				print "INFO: new OU $newOUname already exists. Skipping creation\n";
			} else {
				# Create a new OU with the same attributes as the old one
				my($existsOldOU,$p_OU) = $uMgmt->getJSONPeopleOU($oldOUname);
				
				if($existsOldOU) {
					$p_OU->{'organizationalUnit'} = $newOUname;
					my($createdNewOU,$payload) = $uMgmt->createExtPeopleOU($p_OU);
					
					unless($createdNewOU) {
						print STDERR "ERROR: renaming $oldOUname to $newOUname. Reason:\n";
						foreach my $err (@{$payload}) {
							print STDERR "\t$err\n";
						}
						next;
					}
				} else {
					print STDERR "ERROR: old OU $oldOUname does not exist!\n";
					
					# Next line
					next;
				}
					
			}
			
			# Now, let's get the full list of users in the OU, so we move them one by one
			my($lSuccess,$p_jsonUsers) = $uMgmt->listJSONPeopleOUUsers($oldOUname);
			if($lSuccess) {
				my $worked = 1;
				foreach my $p_jsonUser ( @{$p_jsonUsers} ) {
					my($umSuccess,$payload) = $uMgmt->moveUserToPeopleOU($p_jsonUser->{'username'},$newOUname);
					unless($umSuccess) {
						print STDERR "ERROR: renaming $oldOUname to $newOUname. Reason:\n";
						foreach my $err (@{$payload}) {
							print STDERR "\t$err\n";
						}
						
						$worked = undef;
						last;
					}
				}
				if($worked) {
					print "* OU $oldOUname renamed to $newOUname\n";
					# Last, remove the empty OU
					my($oldRemoved,$payload) = $uMgmt->removePeopleOU($oldOUname);
					unless($oldRemoved) {
						print STDERR "WARNING: Error while removing empty OU $oldOUname\n";
						foreach my $err (@{$payload}) {
							print STDERR "\t$err\n";
						}
					}
				}
			} else {
				print STDERR "ERROR: renaming $oldOUname to $newOUname. Reason:\n";
				foreach my $err (@{$p_jsonUsers}) {
					print STDERR "\t$err\n";
				}
			}
		}
		
		close($OUP);
	} else {
		Carp::croak("ERROR: Unable to open file $ouPairsFile with old -> new OU correspondences. Reason: ".$!);
	}
} else {
	print STDERR "Usage: $0 {IniFile} {Tabular file with pairs of original OU -> new OU (in UTF-8)}\n";
	exit 1;
}

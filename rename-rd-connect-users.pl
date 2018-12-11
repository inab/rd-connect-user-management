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
use RDConnect::TemplateManagement;
use RDConnect::RequestManagement;
use RDConnect::MetaUserManagement;

use constant SECTION	=>	'main';

if(scalar(@ARGV)==2) {
	my $configFile = shift(@ARGV);
	my $userPairsFile = shift(@ARGV);
	
	# Now, let's read all the parameters
	my $cfg = Config::IniFiles->new( -file => $configFile);
	
	# LDAP configuration
	my $uMgmt = RDConnect::UserManagement->new($cfg);
	my $tMgmt = RDConnect::TemplateManagement->new($uMgmt);
	my $rMgmt = RDConnect::RequestManagement->new($tMgmt);
	my $mMgmt = RDConnect::MetaUserManagement->new($rMgmt);
	
	# Read the pairs
	if(open(my $UP,'<:encoding(UTF-8)',$userPairsFile)) {
		while(my $line=<$UP>) {
			# Skipping comment lines
			next  if(substr($line,0,1) eq '#');
			
			chomp($line);
			my($oldUsername,$newUsername) = split(/\t/,$line);
			
			my($success,$p_jsonUser) = $uMgmt->getJSONUser($oldUsername);
			if($success) {
				my($uRepeated) = $uMgmt->getUser($newUsername);
				
				if($uRepeated) {
					print STDERR "ERROR: user $newUsername already exists\n";
				} else {
					$p_jsonUser->{'username'} = $newUsername;
					my($uRenamed,$payload) = $mMgmt->modifyUser($oldUsername,$p_jsonUser);
					if($uRenamed) {
						print "* User $oldUsername renamed to $newUsername\n";
					} else {
						print STDERR "ERROR: renaming $oldUsername to $newUsername. Reason:\n";
						foreach my $err (@{$payload}) {
							print STDERR "\t$err\n";
						}
					}
				}
			} else {
				print STDERR "ERROR: user $oldUsername not found\n";
			}
		}
		
		close($UP);
	} else {
		Carp::croak("ERROR: Unable to open file $userPairsFile with old -> new username correspondences. Reason: ".$!);
	}
} else {
	print STDERR "Usage: $0 {IniFile} {Tabular file with pairs of original username -> new username (in UTF-8)}\n";
	exit 1;
}

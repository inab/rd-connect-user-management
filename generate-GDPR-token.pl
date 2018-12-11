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

if(scalar(@ARGV)==2) {
	my $configFile = shift(@ARGV);
	my $username = shift(@ARGV);
	
	# Now, let's read all the parameters
	my $cfg = Config::IniFiles->new( -file => $configFile);
	
	# LDAP configuration
	my $uMgmt = RDConnect::UserManagement->new($cfg);
	
	my @users = ();
	if(substr($username,0,1) eq '@') {
		my($success,$payload) = $uMgmt->getGroupMembers(substr($username,1));
		if($success) {
			push(@users,@{$payload});
		} else {
			# Reverting state
			foreach my $err (@{$payload}) {
				Carp::carp($err);
			}
			Carp::carp("Unable to find group / role $username. Does it exist?");
		}
	} else {
		my($success,$payload) = $uMgmt->getUser($username);
		if($success) {
			push(@users,$payload);
		} else {
			# Reverting state
			foreach my $err (@{$payload}) {
				Carp::carp($err);
			}
			Carp::carp("Unable to find user $username. Does it exist?");
		}
	}
	
	my $exitval = 0;
	foreach my $user (@users) {
		# Don't send the e-mail to disabled accounts
		next  if($user->get_value('disabledAccount') eq 'TRUE');
		
		my($success,$payload) = $uMgmt->generateGDPRHashFromUser($user);
		my $username = $user->get_value('uid');
		
		if($success) {
			print "$username ===> $payload\n";
		} else {
			print "$username XXXX\n";
			$exitval = 1;
			foreach my $err (@{$payload}) {
				Carp::carp($err);
			}
		}
	}
	
	exit $exitval;
} else {
	die "Usage: $0 {IniFile} {username, user e-mail or \@group name}\n";
}

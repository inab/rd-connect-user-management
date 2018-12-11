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
use Digest;
use MIME::Base64;
use Email::Address;
use Text::Unidecode qw();
use Scalar::Util qw(blessed);

use lib File::Spec->catfile($FindBin::Bin,'libs');
use RDConnect::UserManagement;
use RDConnect::TemplateManagement;
use RDConnect::MetaUserManagement;

use constant SECTION	=>	'main';

if(scalar(@ARGV)>=2) {
	my $configFile = shift(@ARGV);
	my $usersFile = shift(@ARGV);
	
	# LDAP configuration
	my $cfg = Config::IniFiles->new( -file => $configFile);
	my $uMgmt = RDConnect::UserManagement->new($cfg);
	my $tMgmt = RDConnect::TemplateManagement->new($uMgmt);
	my $mMgmt = RDConnect::MetaUserManagement->new($tMgmt);
	
	my $mailTemplateTitle;
	my $mailTemplate;
	my @attachmentFiles;
	
	
	# Read the users
	my @users = ();
	if($usersFile eq '-') {
		my($success,$payload) = $uMgmt->listUsers();
		if($success) {
			@users = @{$payload};
		} else {
			foreach my $err (@{$payload}) {
				Carp::carp($err);
			}
			
			exit 1;
		}
	} elsif(open(my $U,'<:encoding(UTF-8)',$usersFile)) {
		while(my $username=<$U>) {
			# Skipping comments
			next  if(substr($username,0,1) eq '#');
			
			chomp($username);
			
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
		}
		close($U);
	} else {
		Carp::croak("Unable to read file $usersFile");
	}
	
	foreach my $user (@users) {
		# Don't send the e-mail to disabled accounts
		next  if($user->get_value('disabledAccount') eq 'TRUE');
		
		my $username = $user->get_value('uid');
		print "* Preparing and sending e-mail(s) to $username\n";
		my($requestLink,$desistLink,$expiration) = $mMgmt->createGDPRValidationRequest($username);
		
		if($requestLink && !blessed($requestLink)) {
			print "* Acceptance link for $username is valid until $expiration\n";
			print "\t$requestLink\n";
		} else {
			# Reverting state
			use Data::Dumper;
			print STDERR Dumper($requestLink),"\n";
			foreach my $err (@{$desistLink}) {
				Carp::carp($err);
			}
			Carp::carp("Unable to reset GDPR acceptation. What did it happen?");
		}
	}
} else {
	die <<EOF ;
Usage:	$0 [-r] {IniFile} {File with usernames (in UTF-8, one per line)}
EOF
}

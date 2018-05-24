#!/usr/bin/perl

use warnings "all";
use strict;

use Carp;
use Config::IniFiles;
use Digest;
use MIME::Base64;
use Email::Address;
use Text::Unidecode qw();

use FindBin;
use lib $FindBin::Bin . '/libs';
use RDConnect::UserManagement;
use RDConnect::MailManagement;

use constant SECTION	=>	'main';

if(scalar(@ARGV)>=3) {
	my $configFile = shift(@ARGV);
	my $usersFile = shift(@ARGV);
	my $mailTemplate = shift(@ARGV);
	my @attachmentFiles = @ARGV;
	
	my $cfg = Config::IniFiles->new( -file => $configFile);
	
	# Now, let's read all the parameters
	
	# These are the recognized replacements
	my %keyval1 = ( 'username' => '(undefined)', 'gdprtoken' => '(undefined)','fullname' => '(undefined)' );
	
	my $mail1;
	# Mail configuration parameters
	$mail1 = RDConnect::MailManagement->new($cfg,$mailTemplate,\%keyval1,\@attachmentFiles);
	$mail1->setSubject('RD-Connect GDPR Acceptance');
	
	# LDAP configuration
	my $uMgmt = RDConnect::UserManagement->new($cfg);
	
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
		
		my($success,$payload) = $uMgmt->generateGDPRHashFromUser($user);
		
		if($success) {
			my $username = $user->get_value('uid');
			print "* Preparing and sending e-mail(s) to $username (token $payload)\n";
			my $fullname = $user->get_value('cn');
			my(@emails) = $user->get_value('mail');

			# Re-defining the object
			
			$keyval1{'username'} = $username;
			$keyval1{'fullname'} = $fullname;
			$keyval1{'gdprtoken'} = $payload;
			
			foreach my $email (@emails) {
				print "* Sending e-mail to $email\n";
				my $to = Email::Address->new($fullname => $email);
				eval {
					$mail1->sendMessage($to,\%keyval1);
				};
				
				if($@) {
					Carp::carp("Error while sending e-mail to $username ($email): ",$@);
				}
			}
		} else {
			# Reverting state
			foreach my $err (@{$payload}) {
				Carp::carp($err);
			}
			Carp::carp("Unable to reset GDPR acceptation. What did it happen?");
		}
	}
} else {
	die <<EOF ;
Usage:	$0 [-r] {IniFile} {File with usernames (in UTF-8, one per line)} {Message Template} {Attachments}*
EOF
}

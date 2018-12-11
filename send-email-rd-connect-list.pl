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

use lib File::Spec->catfile($FindBin::Bin,'libs');
use RDConnect::MailManagement;

use constant SECTION	=>	'main';

if(scalar(@ARGV)>=4) {
	my $configFile = shift(@ARGV);
	my $tabFile = shift(@ARGV);
	my $templateSubject = shift(@ARGV);
	my $mailTemplate = shift(@ARGV);
	my @attachmentFiles = @ARGV;
	
	my $cfg = Config::IniFiles->new( -file => $configFile);
	
	# Now, let's read all the parameters
	
	# These are the recognized replacements
	my %keyval1 = ( 'fullname' => '(undefined)' );
	
	my $mail1;
	# Mail configuration parameters
	$mail1 = RDConnect::MailManagement->new($cfg,$mailTemplate,\%keyval1,\@attachmentFiles);
	$mail1->setSubject($templateSubject);
	
	# Read the users
	my @users = ();
	if(open(my $U,'<:encoding(UTF-8)',$tabFile)) {
		while(my $line=<$U>) {
			# Skipping comments
			next  if(substr($line,0,1) eq '#');
			
			chomp($line);
			
			my($uid,$isEnabled,$dn,$cn,$givenName,$surname,$emails) = split(/\t/,$line,-1);
			# Translate it into a boolean
			$isEnabled = $isEnabled eq 'ENABLED';
			my @email = split(/;/,$emails,-1);
			
			# Don't send the e-mail to disabled accounts
			push(@users,[$givenName,$surname,\@email])  if($isEnabled);
		}
		close($U);
	} else {
		Carp::croak("Unable to read file $tabFile");
	}
	
	foreach my $user (@users) {
		my $fullname = $user->[0] . ' ' . $user->[1];
		$keyval1{'fullname'} = $fullname;
		foreach my $email (@{$user->[2]}) {
			# Re-defining the object
			my $to = Email::Address->new($fullname => $email);
			
			eval {
				$mail1->sendMessage($to,\%keyval1);
			};
			
			if($@) {
				Carp::carp("Error while sending e-mail to $fullname ($email): ",$@);
			}
		}
	}
} else {
	die <<EOF ;
Usage:	$0 {IniFile} {File in a format like generated from list-rd-connect-users.pl} {Title Template} {Message Template} {Attachments}*
EOF
}

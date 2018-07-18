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

if(scalar(@ARGV)>=3) {
	my $configFile = shift(@ARGV);
	my $tabFile = shift(@ARGV);
	my $mailTemplate = shift(@ARGV);
	my @attachmentFiles = @ARGV;
	
	my $cfg = Config::IniFiles->new( -file => $configFile);
	
	# Now, let's read all the parameters
	
	# These are the recognized replacements
	my %keyval1 = ( 'username' => '(undefined)', 'fullname' => '(undefined)', 'group' => '(undefined)' );
	
	my $mail1;
	# Mail configuration parameters
	$mail1 = RDConnect::MailManagement->new($cfg,$mailTemplate,\%keyval1,\@attachmentFiles);
	$mail1->setSubject('RD-Connect Phenotips platform is online again');
	
	# Read the users
	my @users = ();
	if(open(my $U,'<:encoding(UTF-8)',$tabFile)) {
		while(my $line=<$U>) {
			# Skipping comments
			next  if(substr($line,0,1) eq '#');
			
			$line =~ s/[\n\r]+$//s;
			
			my($emails,$fullname,$username,$ouGroups,$junk) = split(/\t/,$line);
			my($ou,$groups) = split(/,/,$ouGroups,2);
			my @emailArr = split(/[;,]+/,$emails);
			push(@users,[\@emailArr,$fullname,$username,$groups]);
		}
		close($U);
	} else {
		Carp::croak("Unable to read file $tabFile");
	}
	
	foreach my $p_user (@users) {
		my($p_emailArr,$fullname,$username,$groups) = @{$p_user};
		foreach my $email (@{$p_emailArr}) {
			# Re-defining the object
			my $to = Email::Address->new($fullname => $email);
			
			my %keyval = %keyval1;
			$keyval{'username'} = $username;
			$keyval{'fullname'} = $fullname;
			$keyval{'group'} = $groups;
			eval {
				$mail1->sendMessage($to,\%keyval);
			};
			
			if($@) {
				Carp::carp("Error while sending e-mail to $username ($email): ",$@);
			}
		}
	}
} else {
	die <<EOF ;
Usage:	$0 [-r] {IniFile} {Tabular file with usernames (in UTF-8, one per line)} {Message Template} {Attachments}*
EOF
}

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
use constant APGSECTION	=>	'apg';

my $paramPassword;
if(scalar(@ARGV)>0 && $ARGV[0] eq '-p') {
	shift(@ARGV);
	$paramPassword = 1;
}

if((!defined($paramPassword) && scalar(@ARGV)>=2) || (defined($paramPassword) && scalar(@ARGV) == 3)) {
	my $configFile = shift(@ARGV);
	
	my $cfg = Config::IniFiles->new( -file => $configFile);
	
	my $password;
	my @usernames = ();
	if(defined($paramPassword)) {
		push(@usernames,$ARGV[0]);
		$password = $ARGV[1];
	} else {
		@usernames = @ARGV;
	}
	
	# Now, let's read all the parameters
	
	# The digest algorithm
	my $digestAlg = $cfg->val(SECTION,'digest','SHA-1');
	my $digest = Digest->new($digestAlg);
	
	# apg path
	my $apgPath = $cfg->val(APGSECTION,'apgPath','apg');
	my $apgMin = $cfg->val(APGSECTION,'min-length',12);
	my $apgMax = $cfg->val(APGSECTION,'max-length',16);
	
	my @apgParams = ($apgPath,'-m',$apgMin,'-x',$apgMax,'-n',1,'-q');
	
	# These are the recognized replacements
	my %keyval2 = ( 'password' => '(undefined)' );
	
	# Mail configuration parameters
	
	my $passMailTemplate = <<'EOF' ;
The automatically generated password is  [% password %]  (including any punctuation mark it could contain).

You should change this password by a different one as soon as possible.

Kind Regards,
	RD-Connect team
EOF
	my $mail2 = RDConnect::MailManagement->new($cfg,\$passMailTemplate,\%keyval2);
	$mail2->setSubject($mail2->getSubject().' (II)');
	
	# LDAP configuration
	my $uMgmt = RDConnect::UserManagement->new($cfg);
	
	# Read the users
	foreach my $username (@usernames) {
		my $pass;
		if(defined($password)) {
			$pass = $password;
		} elsif(open(my $APG,'-|',@apgParams)) {
			# Now, let's read the generated password
			my $pass = <$APG>;
			chomp($pass);
			close($APG);
		} else {
			Carp::croak("Unable to generate a password using apg\n");
		}
		
		# Setting the digester to a known state
		$digest->reset();
		$digest->add($pass);
		my $digestedPass = '{SHA}'.encode_base64($digest->digest);
		my $user = $uMgmt->resetUserPassword($username,$digestedPass);
		if(defined($user)) {
			unless(defined($password)) {
				my $fullname = $user->get_value('cn');
				my $email = $user->get_value('mail');
				# Re-defining the object
				my $to = Email::Address->new($fullname => $email);
				
				$keyval2{'password'} = $pass;
				eval {
					$mail2->sendMessage($to,\%keyval2);
				};
				if($@) {
					Carp::carp("Error while sending password e-mail: ",$@);
				}
			}
			print "User $username password was reset\n";
		} else {
			# Reverting state
			Carp::carp("Unable to reset password for user $username. Does it exist?");
		}
	}
} else {
	die <<EOF ;
Usage:	$0 {IniFile} {username or user e-mail}+
	$0 {IniFile} -p {username or user e-mail} {new password}
EOF
}

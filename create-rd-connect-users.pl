#!/usr/bin/perl

use warnings "all";
use strict;

use Carp;
use Config::IniFiles;
use Email::Address;
use Text::Unidecode qw();

use FindBin;
use lib $FindBin::Bin . '/libs';
use RDConnect::UserManagement;
use RDConnect::MailManagement;

use constant SECTION	=>	'main';
use constant APGSECTION	=>	'apg';

my $doReplace;
if(scalar(@ARGV)>0 && $ARGV[0] eq '-r') {
	shift(@ARGV);
	$doReplace = 1;
}

my $noEmail;
if(scalar(@ARGV)>0 && $ARGV[0] eq '-n') {
	shift(@ARGV);
	$noEmail = 1;
}

if(scalar(@ARGV)>=3) {
	my $configFile = shift(@ARGV);
	my $usersFile = shift(@ARGV);
	my $mailTemplate = shift(@ARGV);
	my @attachmentFiles = @ARGV;
	
	my $cfg = Config::IniFiles->new( -file => $configFile);
	
	# Now, let's read all the parameters
	
	# apg path
	my $apgPath = $cfg->val(APGSECTION,'apgPath','apg');
	my $apgMin = $cfg->val(APGSECTION,'min-length',12);
	my $apgMax = $cfg->val(APGSECTION,'max-length',16);
	
	my @apgParams = ($apgPath,'-m',$apgMin,'-x',$apgMax,'-n',1,'-q');
	
	# These are the recognized replacements
	my %keyval1 = ( 'username' => '(undefined)', 'fullname' => '(undefined)' );
	my %keyval2 = ( 'password' => '(undefined)' );
	
	my $mail1;
	my $mail2;
	my $NOEMAIL;
	
	if($noEmail) {
		open($NOEMAIL,'>:encoding(UTF-8)',$mailTemplate) || Carp::croak("Unable to create file $mailTemplate");;
	} else {
		# Mail configuration parameters
		$mail1 = RDConnect::MailManagement->new($cfg,$mailTemplate,\%keyval1,\@attachmentFiles);
		$mail1->setSubject($mail1->getSubject().' (I)');
		
		my $passMailTemplate = <<'EOF' ;
The automatically generated password is  [% password %]  (including any punctuation mark it could contain).

You should change this password by a different one as soon as possible.

Kind Regards,
	RD-Connect team
EOF
		$mail2 = RDConnect::MailManagement->new($cfg,\$passMailTemplate,\%keyval2);
		$mail2->setSubject($mail2->getSubject().' (II)');
	}
	
	# LDAP configuration
	my $uMgmt = RDConnect::UserManagement->new($cfg);
	
	# Read the users
	if(open(my $U,'<:encoding(UTF-8)',$usersFile)) {
		while(my $line=<$U>) {
			# Skipping comments
			next  if(substr($line,0,1) eq '#');
			
			chomp($line);
			my($email,$fullname,$username,$ouGroups,$givenName,$sn,$junk) = split(/\t/,$line,7);
			my($ou,$groups) = split(/,/,$ouGroups,2);
			my @addresses = Email::Address->parse($email);
			
			if(scalar(@addresses)==0) {
				Carp::carp("Unable to parse e-mail $email from user $fullname. Skipping");
			} else {
				# The destination user
				my $to = $addresses[0];
				# Re-defining the e-mail
				$email = $to->address();
				
				$fullname = $to->phrase  unless(defined($fullname) && length($fullname)>0);
				# Removing possible spaces before and after the fullname
				$fullname =~ s/^ +//;
				$fullname =~ s/ +$//;
				
				unless(defined($username) && length($username) > 0) {
					my $uniname = lc(Text::Unidecode::unidecode($fullname));
					my @tokens = split(/ +/,$uniname);
					$username = '';
					foreach my $pos (0..($#tokens-1)) {
						$username .= substr($tokens[$pos],0,1) . '.';
					}
					$username .= $tokens[$#tokens];
					
					# Replacing what it is not ASCII 7 alphanumeric characters by dots
					$username =~ tr/a-zA-Z0-9._-/./c;
					
					# Re-defining the values based on the parse step
					# Defining an username
					unless(defined($username) && length($username)>0) {
						$username = $to->address();
						$username = substr($username,0,index($username,'@'));
					}
				}
				
				unless(defined($givenName) && length($givenName)>0 && defined($sn) && length($sn)>0) {
					my $snPoint = rindex($fullname,' ');
					$givenName = substr($fullname,0,$snPoint)  unless(defined($givenName) && length($givenName)>0);
					$sn = substr($fullname,$snPoint+1)  unless(defined($sn) && length($sn)>0);
				}
				
				# Re-defining the object
				$to = Email::Address->new($fullname => $email);
				
				# Now, let's read the generated password
				if(open(my $APG,'-|',@apgParams)) {
					my $pass = <$APG>;
					chomp($pass);
					
					if($uMgmt->createUser($username,$pass,$ou,$fullname,$givenName,$sn,$email,1,$doReplace)) {
						if($NOEMAIL) {
							print $NOEMAIL "$username\t$pass\n";
						} else {
							$keyval1{'username'} = $username;
							$keyval1{'fullname'} = $fullname;
							eval {
								$mail1->sendMessage($to,\%keyval1);
								
								$keyval2{'password'} = $pass;
								eval {
									$mail2->sendMessage($to,\%keyval2);
								};
								if($@) {
									Carp::croak("Error while sending password e-mail: ",$@);
								}
							};
							
							if($@) {
								Carp::croak("Error while sending e-mail: ",$@);
							}
						}
					} else {
						# Reverting state
						Carp::carp("Unable to add user $username (fullname $fullname, e-mail $email). Does it already exist, maybe?");
					}
				} else {
					Carp::croak("Unable to generate a password using apg\n");
				}
			}
		}
		close($U);
	} else {
		Carp::croak("Unable to read file $usersFile");
	}
	close($NOEMAIL)  if($NOEMAIL);
	
} else {
	die <<EOF ;
Usage:	$0 [-r] {IniFile} {Tabular file with new users (in UTF-8)} {Message Template} {Attachments}*
	$0 [-r] -n {IniFile} {Tabular file with new users (in UTF-8)} {New users output file}
EOF
}

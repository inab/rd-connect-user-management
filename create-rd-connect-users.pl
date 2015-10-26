#!/usr/bin/perl

use warnings "all";
use strict;

use Carp;
use Config::IniFiles;
use DBI;
use Digest;
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

if(scalar(@ARGV)>=3) {
	my $configFile = shift(@ARGV);
	my $usersFile = shift(@ARGV);
	my $mailTemplate = shift(@ARGV);
	my @attachmentFiles = @ARGV;
	
	my $cfg = Config::IniFiles->new( -file => $configFile);
	
	# Now, let's read all the parameters
	
	# The database connection parameters
	my $dbistr = $cfg->val(SECTION,'dbistr');
	Carp::croak("dbistr parameter was not defined in $configFile")  unless(defined($dbistr));
	
	my $dbuser = $cfg->val(SECTION,'dbuser','');
	my $dbpass = $cfg->val(SECTION,'dbpass','');
	
	# Database connection
	my $conn = DBI->connect($dbistr,$dbuser,$dbpass,{ RaiseError => 0, AutoCommit => ($doReplace?1:0)});
	
	# Preparing the sentences
	my $insertStr = 'INSERT';
	if($doReplace) {
		print "NOTICE: Replace mode enabled\n";
		$insertStr .= ' OR REPLACE';
	}
	$insertStr .= ' INTO USERS VALUES (?,\'\',?,?,0)';
	my $insSth = $conn->prepare($insertStr);
	
	my $updSth = $conn->prepare('UPDATE USERS SET password=? , active=1 WHERE username=?');
	
	# The digest algorithm
	my $digestAlg = $cfg->val(SECTION,'digest','SHA-1');
	my $digest = Digest->new($digestAlg);
	
	# apg path
	my $apgPath = $cfg->val(APGSECTION,'apgPath','apg');
	my $apgMin = $cfg->val(APGSECTION,'min-length',12);
	my $apgMax = $cfg->val(APGSECTION,'max-length',16);
	
	my @apgParams = ($apgPath,'-m',$apgMin,'-x',$apgMax,'-n',1,'-q');
	
	# These are the recognized replacements
	my %keyval1 = ( 'username' => '(undefined)', 'fullname' => '(undefined)' );
	my %keyval2 = ( 'password' => '(undefined)' );
	
	# Mail configuration parameters
	my $mail1 = RDConnect::MailManagement->new($cfg,$mailTemplate,\%keyval1,\@attachmentFiles);
	$mail1->setSubject($mail1->getSubject().' (I)');
	
	my $passMailTemplate = <<'EOF' ;
The automatically generated password is  [% password %]  (including any punctuation mark it could contain).

You should change this password by a different one as soon as possible.

Kind Regards,
	RD-Connect team
EOF
	my $mail2 = RDConnect::MailManagement->new($cfg,\$passMailTemplate,\%keyval2);
	$mail2->setSubject($mail2->getSubject().' (II)');
	
	# Read the users
	if(open(my $U,'<:encoding(UTF-8)',$usersFile)) {
		while(my $line=<$U>) {
			chomp($line);
			my($email,$fullname,$username,$junk) = split(/\t/,$line,4);
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
				
				# Re-defining the object
				$to = Email::Address->new($fullname => $email);
				
				# Now, let's read the generated password
				if(open(my $APG,'-|',@apgParams)) {
					my $pass = <$APG>;
					chomp($pass);
					
					# Setting the digester to a known state
					$digest->reset();
					$digest->add($pass);
					my $digestedPass = $digest->hexdigest;
					if($insSth->execute($username,$fullname,$email) || $doReplace) {
						if($updSth->execute($digestedPass,$username)) {
							
							$keyval1{'username'} = $username;
							$keyval1{'fullname'} = $fullname;
							eval {
								$mail1->sendMessage($to,\%keyval1);
								
								$keyval2{'password'} = $pass;
								eval {
									$mail2->sendMessage($to,\%keyval2);
									# Now, committing changes
									$conn->commit()  unless(defined($doReplace));
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
						$conn->rollback();
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
	
} else {
	die "Usage: $0 [-r] {IniFile} {Tabular file with new users (in UTF-8)} {Message Template} {Attachments}*"
}

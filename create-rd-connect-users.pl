#!/usr/bin/perl

use warnings "all";
use strict;

use Carp;
use Config::IniFiles;
use DBI;
use Digest;
use Email::Address;
use Email::MIME;
use Email::Sender::Simple qw(sendmail);
use Email::Sender::Transport::SMTPS qw();
use File::Basename qw();
use File::MimeInfo::Magic qw();
use Text::Unidecode qw();

use constant SECTION	=>	'main';
use constant MAILSECTION	=>	'mail';
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
	
	my @apgParams = ($apgPath,'-m',$apgMin,'-x',$apgMax,'-n',1,'-k','-q');
	
	# Mail configuration parameters
	my @mailParams = ();
	foreach my $mailParam ('host','ssl','port','sasl_username','sasl_password') {
		push(@mailParams,$mailParam,$cfg->val(MAILSECTION,$mailParam))  if($cfg->exists(MAILSECTION,$mailParam));
	}
	my $transport = Email::Sender::Transport::SMTPS->new(@mailParams);
	
	my($from) = Email::Address->parse($cfg->val(MAILSECTION,'from'));
	
	Carp::croak("subject field must be defined in order to send e-mails")  unless($cfg->exists(MAILSECTION,'subject'));
	my $subject = $cfg->val(MAILSECTION,'subject');
	
	# Read the mail body
	my $templateMailBodyMime;
	eval {
		$templateMailBodyMime = File::MimeInfo::Magic::mimetype($mailTemplate);
	};
	Carp::croak("ERROR: Unable to pre-process mail template $mailTemplate")  if($@ || !defined($templateMailBodyMime));
	
	my $templateMailBody;
	if(open(my $TT,'<:utf8',$mailTemplate)) {
		local $/;
		$templateMailBody = <$TT>;
		
		close($TT);
	} else {
		Carp::croak("Unable to read template body");
	}
	
	# These are the recognized replacements
	my %keyval = ( 'username' => '(undefined)', 'fullname' => '(undefined)' );
	my %replacements = map { $_ => undef } $templateMailBody =~ /\[% ([a-zA-Z0-9._-]+) %\]/g;
	foreach my $var (keys(%replacements)) {
		Carp::carp("WARNING: annotation $var in template does not exist")  unless(exists($keyval{$var}));
	}
	
	# Identify the attachments
	my @attachments = ();
	foreach my $attachmentFile (@attachmentFiles) {
		my $mime;
		eval {
			$mime = File::MimeInfo::Magic::mimetype($attachmentFile);
		};
		
		Carp::croak("ERROR: Unable to pre-process attachment $attachmentFile")  if($@ || !defined($mime));
		
		if(open(my $AT,'<:raw',$attachmentFile)) {
			local $/;
			push(@attachments,Email::MIME->create(
				attributes => {
					filename => File::Basename::basename($attachmentFile),
					content_type => $mime,
					disposition => "attachment",
					encoding => "base64",
					# name => ,
				},
				body => <$AT>
			));
			
			close($AT);
		} else {
			Carp::croak("ERROR: Unable to read attachment $attachmentFile");
		}
	}
	
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
					$username = Text::Unidecode::unidecode($fullname);
					
					# Replacing apostrophes and commas by points
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
							# Now, committing changes
							$conn->commit()  unless(defined($doReplace));
							
							# Preparing and sending the e-mails
							my $mailBody = $templateMailBody;
							
							# Substitute
							$keyval{'username'} = $username;
							$keyval{'fullname'} = $fullname;
							foreach my $var (keys(%replacements)) {
								my $val = exists($keyval{$var}) ? $keyval{$var} : '(FIXME!)';
								$mailBody =~ s/\Q[% $var %]\E/$val/g;
							}
							
							my $mailPart = Email::MIME->create(
								attributes => {
									encoding => 'quoted-printable',
									content_type => $templateMailBodyMime,
									charset  => 'UTF-8',
								},
								body_str => $mailBody
							);
							
							my $message = Email::MIME->create(
								header_str => [
									From	=>	$from,
									To	=>	$to,
									Subject	=>	$subject.' (I)'
								],
								attributes => {
									content_type => 'multipart/mixed'
								},
								parts => [ $mailPart, @attachments ]
							);
							eval {
								sendmail($message, { from => $from->address(), transport => $transport });
								my $passmessage = Email::MIME->create(
									header_str => [
										From	=>	$from,
										To	=>	$to,
										Subject	=>	$subject.' (II)'
									],
									attributes => {
										encoding => 'quoted-printable',
										charset  => 'ISO-8859-1',
									},
									body_str => <<EOF
The automatically generated password is $pass.

You should change this password by a different one as soon as possible.

Kind Regards,
	RD-Connect team
EOF
								);
								eval {
									sendmail($passmessage, { from => $from->address(), transport => $transport });
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

#!/usr/bin/perl
# RD-Connect User Management Scripts
# José María Fernández (jose.m.fernandez@bsc.es)

use warnings "all";
use strict;

use FindBin;
use File::Spec;
use local::lib File::Spec->catfile($FindBin::Bin,'.plEnv');

use boolean qw();
use Carp;
use Config::IniFiles;
use Email::Address;
use Text::Unidecode qw();

use lib File::Spec->catfile($FindBin::Bin,'libs');
use RDConnect::UserManagement;
use RDConnect::TemplateManagement;
use RDConnect::MetaUserManagement;

use constant SECTION	=>	'main';

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
	
	# LDAP configuration
	my $uMgmt = RDConnect::UserManagement->new($cfg);
	my $tMgmt = RDConnect::TemplateManagement->new($uMgmt);
	my $mMgmt = RDConnect::MetaUserManagement->new($tMgmt);
	
	# Now, let's read all the parameters
	my $NOEMAIL;
	
	if($noEmail) {
		open($NOEMAIL,'>:encoding(UTF-8)',$mailTemplate) || Carp::croak("Unable to create file $mailTemplate");;
	}
	
	# Read the users
	if(open(my $U,'<:encoding(UTF-8)',$usersFile)) {
		my @newUsers = ();
		while(my $line=<$U>) {
			# Skipping comments
			next  if(substr($line,0,1) eq '#');
			
			chomp($line);
			$line =~ s/[\n\r]+$//s;
			my($email,$fullname,$username,$ouGroups,$givenName,$sn,$userCategory,$junk) = split(/\t/,$line,8);
			my($ou,$groups) = split(/,/,$ouGroups,2);
			
			$userCategory = 'Researcher'  unless(defined($userCategory) && length($userCategory) > 0);
			
			# The separator understood by Email::Address is the comma
			$email =~ tr/;/,/;
			my @addresses = Email::Address->parse($email);
			
			my @emails = ();
			if(scalar(@addresses)==0) {
				Carp::carp("Unable to parse e-mail $email from user $fullname. Skipping");
				next;
			} else {
				# The destination user
				my $to = $addresses[0];
				# Re-defining the e-mail
				@emails = map { $_->address() } @addresses;
				
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
			}
			
			my %newUser = (
				'cn'	=>	$fullname,
				'givenName'	=>	[ $givenName ],
				'surname'	=>	[ $sn ],
				'username'	=>	$username,
				'organizationalUnit'	=>	$ou,
				'email'	=>	\@emails,
				'enabled'	=>	boolean::true,
				'userCategory'	=>	$userCategory,
			);
			
			push(@newUsers,\%newUser);
		}
		close($U);
		
		my $retval = $mMgmt->createUser(\@newUsers,$NOEMAIL);
		
		close($NOEMAIL)  if($NOEMAIL);
		
		if(defined($retval)) {
			use Data::Dumper;
			
			Carp::croak($retval->{'reason'}.'. Trace: '.join("\n",map { Dumper($_) } @{(ref($retval->{'trace'}) eq 'ARRAY') ? $retval->{'trace'} : [$retval->{'trace'}]}));
		}
	} else {
		Carp::croak("Unable to read file $usersFile");
	}
	
} else {
	die <<EOF ;
Usage:	$0 [-r] {IniFile} {Tabular file with new users (in UTF-8)} {Message Template} {Attachments}*
	$0 [-r] -n {IniFile} {Tabular file with new users (in UTF-8)} {New users output file}
EOF
}

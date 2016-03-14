#!/usr/bin/perl -w

use strict;

use Carp;
use Config::IniFiles;
use DBI;
use Digest;
use MIME::Base64;

use FindBin;
use lib $FindBin::Bin . '/../libs';
use RDConnect::UserManagement;

use constant SECTION	=>	'main';

my $doReplace;
if(scalar(@ARGV)>0 && $ARGV[0] eq '-r') {
	shift(@ARGV);
	$doReplace = 1;
}

if(scalar(@ARGV)==2) {
	my $configFile = shift(@ARGV);
	my $userPeopleOUFile = shift(@ARGV);
	
	my %userPeople = ();
	if(open(my $UP,'<:encoding(UTF-8)',$userPeopleOUFile)) {
		while(my $line=<$UP>) {
			next  if(substr($line,0,1) eq '#');
			
			chomp($line);
			
			my($userUID,$listOU,$altUserUID,$altListOU,$junk) = split(/\t/,$line,5);
			
			if(defined($altListOU) && length($altListOU) > 0) {
				$userUID = $altUserUID;
				$listOU = $altListOU;
			}
			
			# Only using the OU
			my($peopleOU,$groups) = split(/,/,$listOU);
			
			$userPeople{$userUID} = $peopleOU;
		}
		
		close($UP);
	} else {
		Carp::croak("Unable to open user to organizational units correspondence file $userPeopleOUFile");
	}
	
	my $cfg = Config::IniFiles->new( -file => $configFile);
	
	# Now, let's read all the parameters
	
	# The database connection parameters
	my $dbistr = $cfg->val(SECTION,'dbistr');
	Carp::croak("dbistr parameter was not defined in $configFile")  unless(defined($dbistr));
	
	my $dbuser = $cfg->val(SECTION,'dbuser','');
	my $dbpass = $cfg->val(SECTION,'dbpass','');
	
	# Database connection
	my $conn = DBI->connect($dbistr,$dbuser,$dbpass,{ RaiseError => 0, AutoCommit => 0});
	# This is only for SQLite
	$conn->{'sqlite_unicode'} = 1;
	
	my $selSth = $conn->prepare("SELECT username, password, fullname, email, active FROM USERS");
	
	# The digest algorithm
	my $digestAlg = $cfg->val(SECTION,'digest','SHA-1');
	my $digest = Digest->new($digestAlg);
	
	my $uMgmt = RDConnect::UserManagement->new($cfg);
	
	if($selSth->execute()) {
		my $username;
		my $password;
		my $fullname;
		my $email;
		my $active;
		$selSth->bind_columns(\($username,$password,$fullname,$email,$active));
		
		while($selSth->fetch()) {
			if(exists($userPeople{$username})) {
				my $snPoint = rindex($fullname,' ');
				my $givenName = substr($fullname,0,$snPoint);
				my $sn = substr($fullname,$snPoint+1);
				
				my $bindigest = pack "H*", $password;
				my $hashedPasswd64 = '{SHA}'.encode_base64($bindigest);
				my $groupOU = exists($userPeople{$username})? $userPeople{$username}: undef;
				unless($uMgmt->createUser($username,$hashedPasswd64,$groupOU,$fullname,$givenName,$sn,$email,$active==1,$doReplace)) {
					$conn->rollback();
					Carp::carp("Unable to migrate user $username (does the user already exist?)");
					exit(1);
				}
			}
		}
		$selSth->finish();
		$conn->rollback();
	} else {
		$conn->rollback();
		Carp::croak("Unable to execute fetching query");
	}
	$conn->disconnect();
} else {
	print "Usage: $0 {ini file} {user to peopleOUs correspondence}\n";
}

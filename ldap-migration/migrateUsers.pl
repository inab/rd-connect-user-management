#!/usr/bin/perl -w

use strict;

use Net::LDAP::Entry;

use Carp;
use Config::IniFiles;
use DBI;
use Digest;
use MIME::Base64;
use Net::LDAP;
use Net::LDAP::Entry;

use constant SECTION	=>	'main';
use constant LDAP_SECTION	=>	'ldap';

my $doReplace;
if(scalar(@ARGV)>0 && $ARGV[0] eq '-r') {
	shift(@ARGV);
	$doReplace = 1;
}

my %AcceptedLDAPSchemes = (
	'ldap'	=>	undef,
	'ldaps'	=>	undef,
	'ldapi'	=>	undef,
);

if(scalar(@ARGV)==1) {
	my $configFile = shift(@ARGV);
	
	my $cfg = Config::IniFiles->new( -file => $configFile);
	
	# Now, let's read all the parameters
	
	# The database connection parameters
	my $dbistr = $cfg->val(SECTION,'dbistr');
	Carp::croak("dbistr parameter was not defined in $configFile")  unless(defined($dbistr));
	
	my $dbuser = $cfg->val(SECTION,'dbuser','');
	my $dbpass = $cfg->val(SECTION,'dbpass','');
	
	# Database connection
	my $conn = DBI->connect($dbistr,$dbuser,$dbpass,{ RaiseError => 0, AutoCommit => 0});
	
	my $selSth = $conn->prepare("SELECT username, password, fullname, email, active FROM USERS");
	
	# The digest algorithm
	my $digestAlg = $cfg->val(SECTION,'digest','SHA-1');
	my $digest = Digest->new($digestAlg);
	
	# LDAP connection and configuration parameters
	my @ldap_conn_params = ();
	
	my $ldap_host = $cfg->val(LDAP_SECTION,'ldap_host');
	Carp::croak("ldap_host parameter was not defined in $configFile")  unless(defined($ldap_host));
	
	my $ldap_scheme = $cfg->val(LDAP_SECTION,'ldap_scheme','ldap');
	Carp::croak("Unknown ldap_scheme parameter in $configFile")  unless(exists($AcceptedLDAPSchemes{$ldap_scheme}));
	push(@ldap_conn_params,'scheme' => $ldap_scheme);
	
	my $ldap_port = $cfg->val(LDAP_SECTION,'ldap_port');
	push(@ldap_conn_params,'port' => $ldap_port)  if(defined($ldap_port));
	
	my $start_tls = $cfg->val(LDAP_SECTION,'start_tls','false');
	$start_tls = ($start_tls eq 'true')?1:undef;
	my $ldap_cafile = $cfg->val(LDAP_SECTION,'ldap_cafile');
	Carp::croak("ldap_cafile was not defined")  if($start_tls && !defined($ldap_cafile));
	
	my $ldap_user = $cfg->val(LDAP_SECTION,'ldap_user');
	Carp::croak("ldap_user parameter was not defined in $configFile")  unless(defined($ldap_user));
	my $ldap_pass = $cfg->val(LDAP_SECTION,'ldap_pass');
	Carp::croak("ldap_pass parameter was not defined in $configFile")  unless(defined($ldap_pass));
	
	# The base DNs
	my $userDN = $cfg->val(LDAP_SECTION,'userDN');
	Carp::croak("userDN parameter was not defined in $configFile")  unless(defined($userDN));
	my $groupDN = $cfg->val(LDAP_SECTION,'groupDN');
	Carp::croak("groupDN parameter was not defined in $configFile")  unless(defined($groupDN));
	
	# LDAP connection
	my $ldap = Net::LDAP->new($ldap_host,@ldap_conn_params) || Carp::croak("Unable to connect LDAP host $ldap_host");
	
	$ldap->start_tls(cafile => $ldap_cafile)  if($start_tls && defined($ldap_cafile));
	my $mesg = $ldap->bind($ldap_user,$ldap_pass);
	
	if($selSth->execute()) {
		my $username;
		my $password;
		my $fullname;
		my $email;
		my $active;
		$selSth->bind_columns(\($username,$password,$fullname,$email,$active));
		
		while($selSth->fetch()) {
			my $snPoint = rindex($fullname,' ');
			my $givenName = substr($fullname,0,$snPoint);
			my $sn = substr($fullname,$snPoint+1);
			
			my $bindigest = pack "H*", $password;
			my $hashedPasswd64 = '{SHA}'.encode_base64($bindigest);
			my $entry = Net::LDAP::Entry->new();
			$entry->dn('cn='.$fullname.','.$userDN);
			$entry->add(
				'givenName'	=>	$givenName,
				'sn'	=>	$sn,
				'userPassword'	=>	$hashedPasswd64,
				'objectClass'	=>	 ['basicRDproperties','inetOrgPerson','top'],
				'uid'	=>	$username,
				'disabledAccount'	=>	($active ? 'FALSE':'TRUE'),
				'mail'	=>	$email,
				'cn'	=>	$fullname
			);

			print $entry->ldif();
			
			$entry->update($ldap);
		}
		$selSth->finish();
	} else {
		Carp::croak("Unable to execute fetching query");
	}
} else {
	print "Usage: $0 {ini file}\n";
}

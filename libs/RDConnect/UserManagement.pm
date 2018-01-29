#!/usr/bin/perl -w

use strict;
use v5.10.1;
use experimental 'smartmatch';

use boolean qw();

package RDConnect::UserManagement;

use Carp;
use Config::IniFiles;
use Digest;
use IO::Scalar;
use MIME::Base64;
use Net::LDAP;
use Net::LDAP::Entry;
use Net::LDAP::Util;
use Scalar::Util qw();
use File::MimeInfo::Magic qw();

use constant SECTION	=>	'main';
use constant LDAP_SECTION	=>	'ldap';

my %AcceptedLDAPSchemes = (
	'ldap'	=>	undef,
	'ldaps'	=>	undef,
	'ldapi'	=>	undef,
);

my @LDAP_UTIL_SERIALIZATION_PARAMS = (
	'casefold' => 'lower'
);

# Parameters:
#	cfg: A Config::IniFiles instance
sub new($) {
	my $self = shift;
	my $class = ref($self) || $self;
	
	$self = {}  unless(ref($self));
	
	my $cfg = shift;
	my $configFile = $cfg->GetFileName;
	
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
	my $baseDN = $cfg->val(LDAP_SECTION,'baseDN',"dc=rd-connect,dc=eu");
	Carp::croak("baseDN parameter was not defined in $configFile")  unless(defined($baseDN));
	my $userDN = $cfg->val(LDAP_SECTION,'userDN',"ou=people,dc=rd-connect,dc=eu");
	Carp::croak("userDN parameter was not defined in $configFile")  unless(defined($userDN));
	my $groupDN = $cfg->val(LDAP_SECTION,'groupDN',"ou=groups,dc=rd-connect,dc=eu");
	Carp::croak("groupDN parameter was not defined in $configFile")  unless(defined($groupDN));
	
	my $firstComma = index($userDN,',');
	Carp::croak("unable to infer parentDN parameter from userDN parameter in $configFile")  if($firstComma==-1);
	my $parentDN = substr($userDN,$firstComma + 1);
	
	my $defaultGroupOU = $cfg->val(LDAP_SECTION,'defaultGroupOU','default');
	
	
	# LDAP connection
	my $ldap = Net::LDAP->new($ldap_host,@ldap_conn_params) || Carp::croak("Unable to connect LDAP host $ldap_host");
	
	$ldap->start_tls(cafile => $ldap_cafile)  if($start_tls && defined($ldap_cafile));
	my $mesg = $ldap->bind($ldap_user,'password' => $ldap_pass);
	
	if($mesg->code() != Net::LDAP::LDAP_SUCCESS) {
		use Data::Dumper;
		Carp::croak("Unable bind LDAP host $ldap_host (check credentials?)\n".Dumper($mesg));
	}
	
	# Saving the parameters
	$self->{'cfg'} = $cfg;
	$self->{'ldap'} = $ldap;
	$self->{'userDN'} = $userDN;
	$self->{'groupDN'} = $groupDN;
	$self->{'parentDN'} = $parentDN;
	$self->{'e_userDN'} = Net::LDAP::Util::ldap_explode_dn($userDN,@LDAP_UTIL_SERIALIZATION_PARAMS);
	$self->{'e_groupDN'} = Net::LDAP::Util::ldap_explode_dn($groupDN,@LDAP_UTIL_SERIALIZATION_PARAMS);
	$self->{'defaultGroupOU'} = $defaultGroupOU;
	
	# This one is used to encode passwords in the correct way
	$self->{'digestAlg'} = $cfg->val(SECTION,'digest','SHA-1');

	
	return bless($self,$class);
}

sub getCfg() {
	my $self = shift;
	
	return $self->{'cfg'};
}

sub existsDN($) {
	my $self = shift;
	
	my($dn) = @_;
	my $retval;
	
	my $searchMesg = $self->{'ldap'}->search(
		'base'	=>	$dn,
		'filter'	=>	'(objectClass=*)',
		'scope'	=>	'base',
		'attrs'	=>	[ 'dn' ]
	);
	
	if($searchMesg->code() == Net::LDAP::LDAP_SUCCESS) {
		$retval = $searchMesg->count > 0;
	}
	
	return $retval;
}

my %HASH_MAPPING = (
	'MD5'	=>	'MD5',
	'SHA-1'	=>	'SHA',
	'SSHA'	=>	'SSHA'
);


# This method returns true when password is already properly encoded
sub IsEncodedPassword($) {
	return $_[0] =~ /^\{(?:MD5|S?SHA)\}/;
}

# Generates random password salt - taken from smbldap-passwd.pl
sub __make_salt($) {
	my $length=32;
	$length = $_[0] if exists($_[0]);
	my @tab = ('.', '/', 0..9, 'A'..'Z', 'a'..'z');
	return join "",@tab[map {rand 64} (1..$length)];
}

# Parameters:
#	passwd: The clear password, to be encoded and hashed
sub encodePassword($) {
	my $self = shift;
	
	# The password to encode
	my $passwd = shift;
	
	# The digest algorithm
	unless(exists($self->{_digest})) {
		$self->{_digest} = Digest->new($self->{'digestAlg'} eq 'SSHA' ? 'SHA-1' : $self->{'digestAlg'});
	}
	
	# Generate a different salt on each invocation
	my $salt = undef;
	$salt = __make_salt(4)  if($self->{'digestAlg'} eq 'SSHA');
	
	# Now, let's encode!
	$self->{_digest}->reset();
	$self->{_digest}->add($passwd);
	$self->{_digest}->add($salt)  if(defined($salt));
	
	my $hashedContent = $self->{_digest}->digest;
	$hashedContent .= $salt  if(defined($salt));
	my $digestedPass = '{'.$HASH_MAPPING{$self->{'digestAlg'}}.'}'.encode_base64($hashedContent,'');
	
	return $digestedPass;
}

my @LDAP_USER_DEFAULT_ATTRIBUTES = (
	'objectClass'	=>	 ['basicRDproperties','inetOrgPerson','top','extensibleObject','pwmUser'],
);


# Parameters:
#	username: the RD-Connect username
#	hashedPasswd64: the password, already hashed and represented in the right way
#	groupOU: the ou within userDN where the user entry is going to hang
#	cn: The common name a.k.a. full name
#	givenName: The first name
#	sn: The surname
#	email: The e-mail
#	active: is the user account active
#	doReplace: if true, the entry is an update
sub createUser($$$$$$$;$) {
	my $self = shift;
	
	my($username,$hashedPasswd64,$groupOU,$cn,$givenName,$sn,$email,$active,$doReplace) = @_;
	
	if(defined($groupOU) && length($groupOU) > 0) {
		$groupOU =~ s/^\s+//;
		$groupOU =~ s/\s+$//;
	}
	
	$groupOU = $self->{'defaultGroupOU'}  unless(defined($groupOU) && length($groupOU) > 0);

	$hashedPasswd64 = $self->encodePassword($hashedPasswd64)  unless(IsEncodedPassword($hashedPasswd64));
	
	my $entry = Net::LDAP::Entry->new();
	$entry->changetype('modify')  if($doReplace);
	my $dn = join(',','cn='.Net::LDAP::Util::escape_dn_value($cn),'ou='.Net::LDAP::Util::escape_dn_value($groupOU),$self->{'userDN'});
	$entry->dn($dn);
	$entry->add(
		'givenName'	=>	$givenName,
		'sn'	=>	$sn,
		'userPassword'	=>	$hashedPasswd64,
		'uid'	=>	$username,
		'disabledAccount'	=>	($active ? 'FALSE':'TRUE'),
		'cn'	=>	$cn,
		'mail'	=>	$email,
		@LDAP_USER_DEFAULT_ATTRIBUTES
	);

	my $updMesg = $entry->update($self->{'ldap'});
	if($updMesg->code() != Net::LDAP::LDAP_SUCCESS) {
		print STDERR $entry->ldif();
		
		Carp::carp("Unable to create user $dn (does the user already exist?)\n".Dumper($updMesg));
	}
	return $updMesg->code() == Net::LDAP::LDAP_SUCCESS;
}

# These are done so, in order to create a singleton for the JSON::Validator

{

	use JSON ();
	my $json = undef;
	
	sub getJSONHandler() {
		unless(defined($json)) {
			$json = JSON->new->convert_blessed;
		}
		
		return $json;
	}

}

# http://jsonschemalint.com/draft4/
# http://www.jsonschemavalidator.net/

use File::Spec;

use constant USER_VALIDATION_SCHEMA_FILE	=>	'userValidation.json';
use constant FULL_USER_VALIDATION_SCHEMA_FILE	=>	File::Spec->catfile(File::Basename::dirname(__FILE__),USER_VALIDATION_SCHEMA_FILE);

use constant ENABLED_USERS_SCHEMA_FILE	=>	'enabledUsers.json';
use constant FULL_ENABLED_USERS_SCHEMA_FILE	=>	File::Spec->catfile(File::Basename::dirname(__FILE__),ENABLED_USERS_SCHEMA_FILE);

use constant OU_VALIDATION_SCHEMA_FILE	=>	'organizationalUnitValidation.json';
use constant FULL_OU_VALIDATION_SCHEMA_FILE	=>	File::Spec->catfile(File::Basename::dirname(__FILE__),OU_VALIDATION_SCHEMA_FILE);

use constant GROUP_VALIDATION_SCHEMA_FILE	=>	'groupValidation.json';
use constant FULL_GROUP_VALIDATION_SCHEMA_FILE	=>	File::Spec->catfile(File::Basename::dirname(__FILE__),GROUP_VALIDATION_SCHEMA_FILE);

use constant RDDOCUMENT_VALIDATION_SCHEMA_FILE	=>	'documentValidation.json';
use constant FULL_RDDOCUMENT_VALIDATION_SCHEMA_FILE	=>	File::Spec->catfile(File::Basename::dirname(__FILE__),RDDOCUMENT_VALIDATION_SCHEMA_FILE);
{

	use JSON::Validator;
	use File::Basename ();

	my $userValidator = undef;

	sub getCASUserValidator() {
		unless(defined($userValidator)) {
			my $userSchemaPath = FULL_USER_VALIDATION_SCHEMA_FILE;
			if(-r $userSchemaPath) {
				$userValidator = JSON::Validator->new();
				$userValidator->schema($userSchemaPath);
			}
		}
		
		return $userValidator;
	}

	my $ouValidator = undef;
	
	sub getCASouValidator() {
		unless(defined($ouValidator)) {
			my $ouSchemaPath = FULL_OU_VALIDATION_SCHEMA_FILE;
			if(-r $ouSchemaPath) {
				$ouValidator = JSON::Validator->new();
				$ouValidator->schema($ouSchemaPath);
			}
		}
		
		return $ouValidator;
	}
	
	my $groupValidator = undef;
	
	sub getCASGroupValidator() {
		unless(defined($groupValidator)) {
			my $groupSchemaPath = FULL_GROUP_VALIDATION_SCHEMA_FILE;
			if(-r $groupSchemaPath) {
				$groupValidator = JSON::Validator->new();
				$groupValidator->schema($groupSchemaPath);
			}
		}
		
		return $groupValidator;
	}
	
	my $rdDocumentValidator = undef;
	
	sub getCASRDDocumentValidator() {
		unless(defined($rdDocumentValidator)) {
			my $rdDocumentSchemaPath = FULL_RDDOCUMENT_VALIDATION_SCHEMA_FILE;
			if(-r $rdDocumentSchemaPath) {
				$rdDocumentValidator = JSON::Validator->new();
				$rdDocumentValidator->schema($rdDocumentSchemaPath);
			}
		}
		
		return $rdDocumentValidator;
	}
	
}

# This method fetches the LDAP directory, in order to find the
# correspondence between DNs and their usernames
sub getUIDFromDN($;$) {
	my $self = shift;
	
	my($DN,$beStrict) = shift;
	
	my $retval = undef;
	my $payload = undef;
	
	if(defined($DN)) {
		my $searchMesg = $self->{'ldap'}->search(
			'base' => $DN,
			'filter' => "(objectClass=*)",
			'sizelimit' => 1,
			'scope' => 'base'
		);
		
		if($searchMesg->code() == Net::LDAP::LDAP_SUCCESS) {
			if($searchMesg->count>0) {
				# The entry
				my $entry = $searchMesg->entry(0);
				
				# Now, let's get the uid
				if($entry->exists('uid')) {
					$retval = $entry->get_value('uid');
				} elsif($beStrict) {
					$payload = []  unless(defined($payload));
					push(@{$payload},"Entry $DN does not have a valid username");
				} else {
					# Being permissive
					$retval = $entry->dn();
				}
			} else {
				$payload = []  unless(defined($payload));
				push(@{$payload},"No matching entry found for $DN");
			}
		} else {
			$payload = []  unless(defined($payload));
			push(@{$payload},"Error while finding entry $DN\n".Dumper($searchMesg));
		}
	}
	
	# Show errors when they are not going to be processed upstream
	if(defined($payload) && !wantarray) {
		foreach my $err (@{$payload}) {
			Carp::carp($err);
		}
	}
	
	return wantarray ? ($retval,$payload) : $retval;
}


sub getUIDsFromDNs {
	my $self = shift;
	
	my $p_DNs = shift;
	my $retval = undef;
	my $payload = undef;
	
	if(defined($p_DNs)) {
		$retval = [];
		$p_DNs = [ $p_DNs ]  unless(ref($p_DNs) eq 'ARRAY');
		
		foreach my $DN (@{$p_DNs}) {
			my($partialRetval,$partialPayload) = $self->getUIDFromDN($DN,1);
			
			push(@{$retval}, $partialRetval);
			if(defined($partialPayload)) {
				$payload = []  unless(defined($payload));
				push(@{$payload},@{$partialPayload});
			}
		}
	}
	
	# Show errors when they are not going to be processed upstream
	if(defined($payload) && !wantarray) {
		foreach my $err (@{$payload}) {
			Carp::carp($err);
		}
	}
	
	return wantarray ? ($retval,$payload) : $retval;
}

# This method fetches the LDAP directory, in order to find the
# correspondence between input usernames and their DNs
sub getDNsFromUIDs {
	my $self = shift;
	
	my $p_uids = shift;
	my $retval = undef;
	my $payload = undef;
	
	if(defined($p_uids)) {
		$retval = [];
		$p_uids = [ $p_uids ]  unless(ref($p_uids) eq 'ARRAY');
		
		foreach my $uid (@{$p_uids}) {
			my($success,$partialPayload) = $self->getUser($uid);
			
			if($success) {
				push(@{$retval},$partialPayload->dn());
			} else {
				$payload = []  unless(defined($payload));
				push(@{$payload},@{$partialPayload});
			}
		}
	}
	
	# Show errors when they are not going to be processed upstream
	if(defined($payload) && !wantarray) {
		foreach my $err (@{$payload}) {
			Carp::carp($err);
		}
	}
	
	return wantarray ? ($retval,$payload) : $retval;
}

sub encodePhoto {
	return 'data:image/jpeg;base64,'.encode_base64($_[1],'');
}

sub decodePhoto {
	my $photo = $_[1];
	$photo =~ s/^data:(?:[^\/]+)\/(?:[^\/]+)?(?:;base64)?,//;
	return decode_base64($photo);
}

# Correspondence between JSON attribute names and LDAP attribute names
# and whether these attributes should be masked on return
# Array element meaning:	LDAP attribute name, visible attribute on JSON, array attribute on LDAP, method to translate from JSON to LDAP, method to translate from LDAP to JSON, is read-only
my %JSON_LDAP_USER_ATTRIBUTES = (
	'givenName'	=>	['givenName', boolean::true, boolean::true, undef, undef, boolean::false],
	'surname'	=>	['sn', boolean::true, boolean::true, undef, undef, boolean::false],
	'userPassword'	=>	['userPassword', boolean::false, boolean::false, sub { return (!defined($_[1]) || IsEncodedPassword($_[1])) ? $_[1] : $_[0]->encodePassword($_[1]);}, undef, boolean::false],
	'username'	=>	['uid',boolean::true, boolean::false, undef, undef, boolean::false],
	'enabled'	=>	['disabledAccount',boolean::true, boolean::false, sub { return ($_[1] ? 'FALSE':'TRUE'); }, sub { return (defined($_[1]) && $_[1] eq 'TRUE') ? boolean::false : boolean::true; }, boolean::false],
	'cn'	=>	['cn', boolean::true, boolean::false, undef, undef, boolean::true],
	'email'	=>	['mail',boolean::true, boolean::true, undef, undef, boolean::false],
	
	'userCategory'	=>	['userClass', boolean::true, boolean::false, undef, undef, boolean::false],
	'title'	=>	['title', boolean::true, boolean::false, undef, undef, boolean::false],
	'picture'	=>	['jpegPhoto', boolean::true, boolean::false, \&decodePhoto, \&encodePhoto, boolean::false],
	'telephoneNumber'	=>	['telephoneNumber', boolean::true, boolean::true, undef, undef, boolean::false],
	'facsimileTelephoneNumber'	=>	['facsimileTelephoneNumber', boolean::true, boolean::true, undef, undef, boolean::false],
	'registeredAddress'	=>	['registeredAddress', boolean::true, boolean::false, undef, undef, boolean::false],
	'postalAddress'	=>	['postalAddress', boolean::true, boolean::false, undef, undef, boolean::false],
	'links'	=>	['labeledURI', boolean::true, boolean::true, sub { return [ map { $_->{'uri'}.' '.$_->{'label'}; } @{$_[1]} ]; }, sub { my @retval = (); foreach my $labeledURI (@{$_[1]}) { my @tokens = split(' ',$labeledURI,2); push(@retval,{'uri' => @tokens[0],'label' => @tokens[1]});}; return \@retval; }, boolean::false],
	
	'groups'	=>	['memberOf', boolean::true, boolean::true, undef, sub { return [ map { _getCNFromGroupDN($_); } @{$_[1]} ]; }, boolean::true],
	'organizationalUnit'	=>	[undef, boolean::true, boolean::false, undef, undef, boolean::true],
);

# Inverse correspondence: LDAP attributes to JSON ones
my %LDAP_JSON_USER_ATTRIBUTES = map { $JSON_LDAP_USER_ATTRIBUTES{$_}[0] => [ $_, @{$JSON_LDAP_USER_ATTRIBUTES{$_}}[1..$#{$JSON_LDAP_USER_ATTRIBUTES{$_}}] ]} grep { defined($JSON_LDAP_USER_ATTRIBUTES{$_}->[0])? 1 : undef; } keys(%JSON_LDAP_USER_ATTRIBUTES);


my %JSON_LDAP_ENABLED_USERS_ATTRIBUTES = (
	'title'	=>	['title', boolean::true, boolean::false, undef, undef, boolean::true],
	'fullname'	=>	['cn', boolean::true, boolean::false, undef, undef, boolean::true],
	'username'	=>	['uid',boolean::true, boolean::false, undef, undef, boolean::true],
	'organizationalUnit'	=>	[undef, boolean::true, boolean::false, undef, undef, boolean::true],
	
	'userCategory'	=>	['userClass', boolean::true, boolean::false, undef, undef, boolean::true],
	
	'email'	=>	['mail',boolean::true, boolean::true, undef, undef, boolean::true],
);

# Inverse correspondence: LDAP attributes to JSON ones
my %LDAP_JSON_ENABLED_USERS_ATTRIBUTES = map { $JSON_LDAP_ENABLED_USERS_ATTRIBUTES{$_}[0] => [ $_, @{$JSON_LDAP_ENABLED_USERS_ATTRIBUTES{$_}}[1..$#{$JSON_LDAP_ENABLED_USERS_ATTRIBUTES{$_}}] ]} grep { defined($JSON_LDAP_ENABLED_USERS_ATTRIBUTES{$_}->[0])? 1 : undef; } keys(%JSON_LDAP_ENABLED_USERS_ATTRIBUTES);

my %JSON_LDAP_OU_ATTRIBUTES = (
	'organizationalUnit'	=>	['ou', boolean::true, boolean::false, undef, undef, boolean::true],
	'description'	=>	['description', boolean::true, boolean::false, undef, undef, boolean::false],
	'picture'	=>	['jpegPhoto', boolean::true, boolean::false,  \&decodePhoto, \&encodePhoto, boolean::false],
	'links'	=>	['labeledURI', boolean::true, boolean::true, sub { return [ map { $_->{'uri'}.' '.$_->{'label'}; } @{$_[1]} ]; }, sub { my @retval = (); foreach my $labeledURI (@{$_[1]}) { my @tokens = split(' ',$labeledURI,2); push(@retval,{'uri' => @tokens[0],'label' => @tokens[1]});}; return \@retval; }, boolean::false],
);

my %LDAP_JSON_OU_ATTRIBUTES = map { $JSON_LDAP_OU_ATTRIBUTES{$_}[0] => [ $_, @{$JSON_LDAP_OU_ATTRIBUTES{$_}}[1..$#{$JSON_LDAP_OU_ATTRIBUTES{$_}}] ]} grep { defined($JSON_LDAP_OU_ATTRIBUTES{$_}->[0])? 1 : undef; } keys(%JSON_LDAP_OU_ATTRIBUTES);


my %JSON_LDAP_GROUP_ATTRIBUTES = (
	'cn'	=>	['cn', boolean::true, boolean::false, undef, undef, boolean::true],
	'description'	=>	['description', boolean::true, boolean::false, undef, undef, boolean::false],
	'groupPurpose'	=>	['businessCategory',boolean::true, boolean::false, undef, undef, boolean::false],
	'owner'	=>	['owner', boolean::true, boolean::true, \&getDNsFromUIDs, \&getUIDsFromDNs, boolean::true],
	'members'	=>	['member', boolean::true, boolean::true, \&getDNsFromUIDs, \&getUIDsFromDNs, boolean::true],
);

my %LDAP_JSON_GROUP_ATTRIBUTES = map { $JSON_LDAP_GROUP_ATTRIBUTES{$_}[0] => [ $_, @{$JSON_LDAP_GROUP_ATTRIBUTES{$_}}[1..$#{$JSON_LDAP_GROUP_ATTRIBUTES{$_}}] ]} grep { defined($JSON_LDAP_GROUP_ATTRIBUTES{$_}->[0])? 1 : undef; } keys(%JSON_LDAP_GROUP_ATTRIBUTES);


my %JSON_LDAP_RDDOCUMENT_ATTRIBUTES = (
	'cn'	=>	['cn', boolean::true, boolean::false, undef, undef, boolean::true],
	'description'	=>	['description', boolean::true, boolean::false, undef, undef, boolean::false],
	'documentClass'	=>	['documentClass', boolean::true, boolean::false, undef, undef, boolean::false],
	'creationTimestamp'	=>	['createTimestamp', boolean::true, boolean::false, undef, \&_LDAP_ISO8601_RFC3339, boolean::true],
	'modificationTimestamp'	=>	['modifyTimestamp', boolean::true, boolean::false, undef, \&_LDAP_ISO8601_RFC3339, boolean::true],
	'owner'	=>	['owner', boolean::true, boolean::false, undef, \&getUIDFromDN, boolean::true],
	'creator'	=>	['creatorsName', boolean::true, boolean::false, undef, \&getUIDFromDN, boolean::true],
	'modifier'	=>	['modifiersName', boolean::true, boolean::false, undef, \&getUIDFromDN, boolean::true],
);

my %LDAP_JSON_RDDOCUMENT_ATTRIBUTES = map { $JSON_LDAP_RDDOCUMENT_ATTRIBUTES{$_}[0] => [ $_, @{$JSON_LDAP_RDDOCUMENT_ATTRIBUTES{$_}}[1..$#{$JSON_LDAP_RDDOCUMENT_ATTRIBUTES{$_}}] ]} grep { defined($JSON_LDAP_RDDOCUMENT_ATTRIBUTES{$_}->[0])? 1 : undef; } keys(%JSON_LDAP_RDDOCUMENT_ATTRIBUTES);

# Hotchpotches

use constant USER_HOTCHPOTCH_ATTRIBUTE	=> 	'jsonData';

# Other constants
use constant USER_MEMBEROF_ATTRIBUTE	=>	'memberOf';

# And now, methods (again)!

sub _getParentDNFromDN($) {
	my($dn) = @_;
	
	my $p_components = Net::LDAP::Util::ldap_explode_dn($dn,@LDAP_UTIL_SERIALIZATION_PARAMS);
	shift(@{$p_components});
	
	return Net::LDAP::Util::canonical_dn($p_components,@LDAP_UTIL_SERIALIZATION_PARAMS);
}

sub _getParentOUFromDN($) {
	my($dn) = @_;
	
	my $p_components = Net::LDAP::Util::ldap_explode_dn($dn,@LDAP_UTIL_SERIALIZATION_PARAMS);
	shift(@{$p_components});
	
	return exists($p_components->[0]{'ou'}) ? $p_components->[0]{'ou'} : undef;
}

sub _getCNFromGroupDN($) {
	my($dn) = @_;
	
	my $p_components = Net::LDAP::Util::ldap_explode_dn($dn,@LDAP_UTIL_SERIALIZATION_PARAMS);
	
	return exists($p_components->[0]{'cn'}) ? $p_components->[0]{'cn'} : undef;
}

sub _getUserDNFromJSON($\%) {
	my $uMgmt = shift;
	
	my($jsonUser) = @_;
	my $cn = exists($jsonUser->{'cn'}) ? $jsonUser->{'cn'} : '';
	
	my $dn = join(',','cn='.Net::LDAP::Util::escape_dn_value($cn),'ou='.Net::LDAP::Util::escape_dn_value($jsonUser->{'organizationalUnit'}),$uMgmt->{'userDN'});
	
	return $dn;
}

sub _getPeopleOUDNFromJSON($\%) {
	my $uMgmt = shift;
	
	my($jsonPeopleOU) = @_;
	my $ou = exists($jsonPeopleOU->{'organizationalUnit'}) ? $jsonPeopleOU->{'organizationalUnit'} : '';
	
	my $dn = join(',','ou='.Net::LDAP::Util::escape_dn_value($ou),$uMgmt->{'userDN'});
	
	return $dn;
}

sub _getGroupDNFromJSON($\%) {
	my $uMgmt = shift;
	
	my($jsonGroup) = @_;
	my $cn = exists($jsonGroup->{'cn'}) ? $jsonGroup->{'cn'} : '';
	
	my $dn = join(',','cn='.Net::LDAP::Util::escape_dn_value($cn),$uMgmt->{'groupDN'});
	
	return $dn;
}

sub _normalizeUserCNFromJSON(\%) {
	my($jsonUser) = @_;
	
	unless(exists($jsonUser->{'cn'}) && length($jsonUser->{'cn'}) > 0) {
		my $givenName = ref($jsonUser->{'givenName'}) eq 'ARRAY' ? join(' ',@{$jsonUser->{'givenName'}}) : $jsonUser->{'givenName'};
		my $surname = ref($jsonUser->{'surname'}) eq 'ARRAY' ? join(' ',@{$jsonUser->{'surname'}}) : $jsonUser->{'surname'};
		$jsonUser->{'cn'} = $givenName .' '.$surname;
	}
}

sub _LDAP_ISO8601_RFC3339($$) {
	my($uMgmt,$timestamp) = @_;
	
	if($timestamp =~ /^([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z/) {
		$timestamp = join('-',$1,$2,$3).'T'.join(':',$4,$5,$6).'Z';
	}
	
	return $timestamp;
}


sub newUserConsistency($) {
	my $self = shift;
	
	my($p_entryHash) = @_;
	
	my @reterr = ();
	
	foreach my $userToken ($p_entryHash->{'username'},@{$p_entryHash->{'email'}}) {
		my($success,$partialPayload) = $self->getUser($userToken);
		
		push(@reterr,"User token $userToken is already in use")  if($success);
	}
	
	return @reterr;
}

# Parameters:
#	p_entryArray: a reference to a hash or an array of hashes with the required keys needed to create new users
#	m_getDN: a method which computes the DN of the new entries
#	m_normalizePKJSON: a method which normalizes the primary key, which is part of the DN
#	validator: an instance of JSON::Validator for this type of entries
#	consistencyValidator: name of a consistency validation method, in order to check against the whole LDAP directory
#	p_json2ldap: a reference to the correspondence from JSON to LDAP for this type of entry
#	hotchpotchAttribute: The name of the hotchpotch attribute (if any)
#	p_ldap_default_attributes: The default attributes to always set
#	doReplace: if true, the entry is an update
sub createLDAPFromJSON(\[%@]$$$$\%$\@;$) {
	my $self = shift;
	
	my($p_entryArray,$m_getDN,$m_normalizePKJSON,$validator,$consistencyValidator,$p_json2ldap,$hotchpotchAttribute,$p_ldap_default_attributes,$doReplace) = @_;
	#my($username,$hashedPasswd64,$groupOU,$cn,$givenName,$sn,$email,$active,$doReplace) = @_;
	
	if(ref($p_entryArray) ne 'ARRAY') {
		if(ref($p_entryArray) eq 'HASH') {
			$p_entryArray = [ $p_entryArray ];
		} else {
			my $p_err = ['Input JSON entry must be either an array or a hash ref!'];
			if(wantarray) {
				return (undef,$p_err);
			} else {
				foreach my $err (@{$p_err}) {
					Carp::carp($err);
				}
				return undef;
			}
		}
	}
	
	# First pass, validation
	my $failed = undef;
	my $p_err = [];
	foreach my $p_entryHash (@{$p_entryArray}) {
		# Breaking when something cannot be validated
		unless(ref($p_entryHash) eq 'HASH') {
			$failed = 1;
			push(@{$p_err},'All the input entries in an array must be hash refs!');
			next;
		}
		
		# GroupOU normalization
		if(exists($p_json2ldap->{'organizationalUnit'})) {
			my $groupOU = exists($p_entryHash->{'organizationalUnit'}) ? $p_entryHash->{'organizationalUnit'} : undef;
			if(defined($groupOU) && length($groupOU) > 0) {
				$groupOU =~ s/^\s+//;
				$groupOU =~ s/\s+$//;
			}
			
			$groupOU = $self->{'defaultGroupOU'}  unless(defined($groupOU) && length($groupOU) > 0);
			$p_entryHash->{'organizationalUnit'} = $groupOU;
		}
		
		foreach my $entryKey (keys(%{$p_entryHash})) {
			if(Scalar::Util::blessed($p_entryHash->{$entryKey}) && $p_entryHash->{$entryKey}->isa('boolean')) {
				use JSON::PP;
				
				$p_entryHash->{$entryKey} = $p_entryHash->{$entryKey} ? $JSON::PP::true : $JSON::PP::false;
			}
		}
		
		# Now, the validation of each input
		my @valErrors = $validator->validate($p_entryHash);
		if(scalar(@valErrors) > 0) {
			$failed = 1;
			
			my $dn = $m_getDN->($self,$p_entryHash);
			
			push(@{$p_err},"Validation errors for not created entry $dn\n".join("\n",map { "\tPath: ".$_->{'path'}.' . Message: '.$_->{'message'}} @valErrors));
		}
		
		unless($failed) {
			# cn normalization
			$m_normalizePKJSON->($p_entryHash)  if(ref($m_normalizePKJSON) eq 'CODE');
			
			push(@{$p_err},'');
			
			# Consistency validator
			if(defined($consistencyValidator) && $self->can($consistencyValidator)) {
				my @reterr = $self->$consistencyValidator($p_entryHash);
				
				if(scalar(@reterr) > 0) {
					$failed = 1;
					
					my $dn = $m_getDN->($self,$p_entryHash);
					
					push(@{$p_err},"Consistency errors for not created entry $dn\n".join("\n",@reterr));
				}
			}
		}
	}
	if($failed) {
		if(wantarray) {
			return (undef,$p_err);
		} else {
			foreach my $err (@{$p_err}) {
				Carp::carp($err);
			}
			return undef;
		}
	}
	
	# Second pass, user creation
	my $j = getJSONHandler();
	foreach my $p_entryHash (@{$p_entryArray}) {
		# Let's work!
		my $entry = Net::LDAP::Entry->new();
		$entry->changetype('modify')  if($doReplace);
		
		my $dn = $m_getDN->($self,$p_entryHash);
		$entry->dn($dn);
		
		my @ldapAttributes = ();
		
		# First, the common LDAP attributes
		push(@ldapAttributes,@{$p_ldap_default_attributes});
		
		# Next, the attributes which go straight to LDAP
		foreach my $jsonKey (keys(%{$p_entryHash})) {
			if(exists($p_json2ldap->{$jsonKey}) && defined($p_json2ldap->{$jsonKey}[0])) {
				my $ldapVal = $p_entryHash->{$jsonKey};
				$ldapVal = [ $ldapVal ]  if($p_json2ldap->{$jsonKey}[2] && !ref($ldapVal) eq 'ARRAY');
				if(defined($p_json2ldap->{$jsonKey}[3])) {
					my $retval = undef;
					($ldapVal,$retval) = $p_json2ldap->{$jsonKey}[3]->($self,$ldapVal);
					
					if(defined($retval)) {
						if(wantarray) {
							return (undef,$retval);
						} else {
							foreach my $err (@{$retval}) {
								Carp::carp($err);
							}
							return undef;
						}
					}
				}
				push(@ldapAttributes,$p_json2ldap->{$jsonKey}[0] => $ldapVal);
			}
		}
		
		# Last, mask attributes and store the whole JSON in the hotchpotch
		foreach my $jsonKey (keys(%{$p_json2ldap})) {
			if(exists($p_entryHash->{$jsonKey})) {
				my $p_jsonDesc = $p_json2ldap->{$jsonKey};
				unless($p_jsonDesc->[1]) {
					#$p_entryHash->{$jsonKey} = undef;
					delete($p_entryHash->{$jsonKey});
				}
			}
		}
		push(@ldapAttributes, $hotchpotchAttribute => $j->encode($p_entryHash))  if(defined($hotchpotchAttribute));
		
		$entry->add(@ldapAttributes);
		
		my $updMesg = $entry->update($self->{'ldap'});
		if($updMesg->code() != Net::LDAP::LDAP_SUCCESS) {
			$p_err = [ "Unable to create entry $dn (does the entry already exist?)\n".Dumper($updMesg) ];
			if(wantarray) {
				return (undef,$p_err);
			} else {
				print STDERR $entry->ldif();
				
				foreach my $err (@{$p_err}) {
					Carp::carp($err);
				}
				return undef;
			}
		}
	}
	
	return wantarray ? (1,$p_entryArray) : 1;
}


# Parameters:
#	p_userArray: a reference to a hash or an array of hashes with the required keys needed to create new users
#	doReplace: (OPTIONAL) if true, the entry is an update
sub createExtUser(\[%@];$) {
	my $self = shift;
	my($p_userArray,$doReplace) = @_;
	
	# $p_entryArray,$m_getDN,$m_normalizePKJSON,$validator,$p_json2ldap,$hotchpotchAttribute,$p_ldap_default_attributes,$doReplace
	return $self->createLDAPFromJSON(
				$p_userArray,
				\&_getUserDNFromJSON,
				\&_normalizeUserCNFromJSON,
				getCASUserValidator(),
				'newUserConsistency',
				\%JSON_LDAP_USER_ATTRIBUTES,
				USER_HOTCHPOTCH_ATTRIBUTE,
				\@LDAP_USER_DEFAULT_ATTRIBUTES,
				$doReplace
			);
}


# Parameters:
#	p_entries: a list of LDAP objects
#	p_ldap2json: a hash describing the translation from LDAP to JSON
#	m_postfixup: a post fixup method, which takes the whole LDAP entry
#	hotchpotchAttribute: The name of the hotchpotch attribute, if any
#	as_hash: Return a hash instead of an array reference, using the value
#		of this parameter as the key
# It returns an array of JSON user entries
sub genJSONFromLDAP(\@\%;$$$) {
	my $self = shift;
	
	my($p_entries,$p_ldap2json,$m_postFixup,$hotchpotchAttribute,$as_hash) = @_;
	
	my @retval = ();
	
	my $j = getJSONHandler();
	my $doPostFixup = ref($m_postFixup) eq 'CODE';
	foreach my $entry (@{$p_entries}) {
		my $jsonEntry = {};
		if(defined($hotchpotchAttribute) && $entry->exists($hotchpotchAttribute)) {
			# This could fail, after all
			eval {
				$jsonEntry = $j->decode($entry->get_value($hotchpotchAttribute)); 
			};
		}
		
		foreach my $ldapKey (keys(%{$p_ldap2json})) {
			my $ldapDesc = $p_ldap2json->{$ldapKey};
			
			if($entry->exists($ldapKey)) {
				# Only processing those LDAP attributes which are exportable
				if($ldapDesc->[1]) {
					# LDAP attribute values always take precedence over JSON ones
					my @values = $entry->get_value($ldapKey);
					my $theVal = $ldapDesc->[2] ? \@values : $values[0];
					if(defined($ldapDesc->[4])) {
						my $retval = undef;
						($theVal, $retval) = $ldapDesc->[4]->($self,$theVal);
						
						if(defined($retval)) {
							Carp::carp("Error postprocessing LDAP key $ldapKey");
							foreach my $err (@{$retval}) {
								Carp::carp($err);
							}
						}
					}
					
					$jsonEntry->{$ldapDesc->[0]} = $theVal;
				#} else {
				#	$jsonEntry->{$ldapDesc->[0]} = undef;
				}
			} elsif(exists($jsonEntry->{$ldapDesc->[0]})) {
				# Removing spureous key not any valid
				delete($jsonEntry->{$ldapDesc->[0]});
			}
		}
		
		# Last, but not the least important, the organizationalUnit
		$m_postFixup->($self,$entry,$jsonEntry)  if($doPostFixup);
		
		push(@retval,$jsonEntry);
	}
	
	return defined($as_hash) ? { $as_hash => \@retval } : \@retval;
}

sub postFixupUser($$) {
	my($uMgmt,$entry,$jsonEntry) = @_;
	$jsonEntry->{'organizationalUnit'} = _getParentOUFromDN($entry->dn());
}

sub postFixupDocument($$) {
	my($uMgmt,$entry,$jsonEntry) = @_;
	my $payload;
	($jsonEntry->{'owner'},$payload) = $uMgmt->getUIDFromDN(_getParentDNFromDN($entry->dn()));
	#print STDERR Dumper($payload),"\n";
}

sub genJSONUsersFromLDAPUsers(\@) {
	my $self = shift;
	
	return $self->genJSONFromLDAP($_[0], \%LDAP_JSON_USER_ATTRIBUTES, \&postFixupUser, USER_HOTCHPOTCH_ATTRIBUTE);
}

sub genJSONEnabledUsersFromLDAPUsers(\@) {
	my $self = shift;
	
	return $self->genJSONFromLDAP($_[0], \%LDAP_JSON_ENABLED_USERS_ATTRIBUTES, \&postFixupUser, undef, 'results');
}

sub genJSONouFromLDAPou(\@) {
	my $self = shift;
	
	return $self->genJSONFromLDAP($_[0], \%LDAP_JSON_OU_ATTRIBUTES);
}

sub genJSONGroupsFromLDAPGroups(\@) {
	my $self = shift;
	
	return $self->genJSONFromLDAP($_[0], \%LDAP_JSON_GROUP_ATTRIBUTES);
}

sub genJSONDocumentsFromLDAPDocuments(\@) {
	my $self = shift;
	
	return $self->genJSONFromLDAP($_[0], \%LDAP_JSON_RDDOCUMENT_ATTRIBUTES, \&postFixupDocument);
}

# Parameters:
#	jsonEntry: the JSON entry
#	entry: the LDAP entry
#	p_entryHash: a reference to a hash with the modified entry information
#	validator: an instance of JSON::Validator for this type of entry
#	p_json2ldap: a reference to the correspondence from JSON to LDAP for this type of entry
#	hotchpotchAttribute: The name of the hotchpotch attribute (if any)
#	p_ldap_default_attributes: The default attributes to always set
#	p_removedKeys: a reference to an array with the removed keys
# It returns the LDAP entry of the user on success
sub modifyJSONEntry(\%$\%$\%$\@;\@) {
	my $self = shift;
	
	my($jsonEntry,$entry,$p_entryHash,$p_json2ldap,$validator,$hotchpotchAttribute,$p_ldap_default_attributes,$p_removedKeys) = @_;
	
	my $success = undef;
	my $payload = [];
	my $payload2;
	
	if(ref($p_entryHash) eq 'HASH' && (!defined($p_removedKeys) || ref($p_removedKeys) eq 'ARRAY')) {
		$success = 1;
		$payload = [];
		
		# Now, apply the changes
		my $modifications = undef;
		my @addedLDAPAttributes = ();
		my @modifiedLDAPAttributes = ();
		my @removedLDAPAttributes = ();
		
		# Labelling keys to be removed
		if(ref($p_removedKeys) eq 'ARRAY') {
			foreach my $jsonKey (@{$p_removedKeys}) {
				# Skipping modifications on banned keys or read-only ones
				next  if(exists($p_json2ldap->{$jsonKey}) && (!$p_json2ldap->{$jsonKey}[1] || $p_json2ldap->{$jsonKey}[5]));
				
				$p_entryHash->{$jsonKey} = undef;
			}
		}
		
		# Detect modified attributes
		foreach my $jsonKey (keys(%{$p_entryHash})) {
			# Skipping modifications on banned keys or read-only ones
			next  if(exists($p_json2ldap->{$jsonKey}) && (!$p_json2ldap->{$jsonKey}[1] || $p_json2ldap->{$jsonKey}[5]));
			
			# Small fix for JSON::Validator, which does not expect boolean values
			if(Scalar::Util::blessed($jsonEntry->{$jsonKey}) && $jsonEntry->{$jsonKey}->isa('boolean')) {
				use JSON::PP;
				
				$jsonEntry->{$jsonKey} = $jsonEntry->{$jsonKey} ? $JSON::PP::true : $JSON::PP::false;
			}
			
			my $doModify = undef;
			if(!exists($jsonEntry->{$jsonKey}) || !defined($p_entryHash->{$jsonKey})) {
				$doModify = 1;
			} elsif((Scalar::Util::blessed($jsonEntry->{$jsonKey}) && $jsonEntry->{$jsonKey}->isa('JSON::PP::Boolean')) || (Scalar::Util::blessed($p_entryHash->{$jsonKey}) && $p_entryHash->{$jsonKey}->isa('JSON::PP::Boolean'))) {
				$doModify = ($jsonEntry->{$jsonKey} && !$p_entryHash->{$jsonKey}) || (!$jsonEntry->{$jsonKey} && $p_entryHash->{$jsonKey});
			} else {
				$doModify = !($jsonEntry->{$jsonKey} ~~ $p_entryHash->{$jsonKey});
			}
			
			if($doModify) {
				$modifications = 1;
				
				if(defined($p_entryHash->{$jsonKey})) {
					# This is also an LDAP attribute modification
					if(exists($p_json2ldap->{$jsonKey})) {
						my $ldapVal = $p_entryHash->{$jsonKey};
						$ldapVal = [ $ldapVal ]  if($p_json2ldap->{$jsonKey}[2] && !ref($ldapVal) eq 'ARRAY');
						if(defined($p_json2ldap->{$jsonKey}[3])) {
							my $retval = undef;
							($ldapVal,$retval) = $p_json2ldap->{$jsonKey}[3]->($self,$ldapVal);
							
							# Were there processing errors?
							if(defined($retval)) {
								$success = undef;
								push(@{$payload},"Error on key $jsonKey post-processing",@{$retval});
							}
						}
						
						if(exists($jsonEntry->{$jsonKey})) {
							push(@modifiedLDAPAttributes, $p_json2ldap->{$jsonKey}[0] => $ldapVal);
						} else {
							push(@addedLDAPAttributes, $p_json2ldap->{$jsonKey}[0] => $ldapVal);
						}
					}
					
					$jsonEntry->{$jsonKey} = $p_entryHash->{$jsonKey};
				} else {
					delete($jsonEntry->{$jsonKey});
					
					# This is an attribute removal
					if(exists($p_json2ldap->{$jsonKey})) {
						push(@removedLDAPAttributes,$p_json2ldap->{$jsonKey}[0]);
					}
				}
			}
		}
		
		if($success) {
			if($modifications) {
				# Before any modification, let's validate
				my @valErrors = $validator->validate($jsonEntry);
				
				if(scalar(@valErrors) > 0) {
					$success = undef;
					
					my $dn = $entry->dn();
					
					$payload = [ "Validation errors for modifications on entry $dn\n".join("\n",map { "\tPath: ".$_->{'path'}.' . Message: '.$_->{'message'}} @valErrors) ];
				} else {
					# cn normalization (disabled)
					#unless(exists($p_userHash->{'cn'}) && length($p_userHash->{'cn'}) > 0) {
					#	my $givenName = ref($p_userHash->{'givenName'}) eq 'ARRAY' ? join(' ',@{$p_userHash->{'givenName'}}) : $p_userHash->{'givenName'};
					#	my $surname = ref($p_userHash->{'surname'}) eq 'ARRAY' ? join(' ',@{$p_userHash->{'surname'}}) : $p_userHash->{'surname'};
					#	$p_userHash->{'cn'} = $givenName .' '.$surname;
					#	
					#	push(@modifiedLDAPAttributes, $JSON_LDAP_USER_ATTRIBUTES{'cn'}[0] => $p_userHash->{'cn'});
					#}
					
					# Mask attributes and store the whole JSON in the hotchpotch
					foreach my $jsonKey (keys(%{$p_json2ldap})) {
						if(exists($jsonEntry->{$jsonKey})) {
							my $p_jsonDesc = $p_json2ldap->{$jsonKey};
							unless($p_jsonDesc->[1]) {
								#$jsonEntry->{$jsonKey} = undef;
								delete($jsonEntry->{$jsonKey});
							}
						}
					}
					
					if(defined($hotchpotchAttribute)) {
						my $j = getJSONHandler();
						push(@modifiedLDAPAttributes, $hotchpotchAttribute => $j->encode($jsonEntry));
					}
					
					# These are needed to upgrade the entry
					#push(@modifiedLDAPAttributes, @{$p_ldap_default_attributes});
					
					# Now, let's modify the LDAP entry
					my $dn = $entry->dn();
					$entry->changetype('modify');
					$entry->replace(@{$p_ldap_default_attributes});
					
					my $updMesg = $entry->update($self->{'ldap'});
					if($updMesg->code() == Net::LDAP::LDAP_SUCCESS) {
						# The batch of modifications
						$entry->changetype('modify');
						$entry->add(@addedLDAPAttributes)  if(scalar(@addedLDAPAttributes) > 0);
						$entry->replace(@modifiedLDAPAttributes)  if(scalar(@modifiedLDAPAttributes) > 0);
						$entry->delete(map { $_ => undef; } @removedLDAPAttributes)  if(scalar(@removedLDAPAttributes) > 0);
						
						$updMesg = $entry->update($self->{'ldap'});
						if($updMesg->code() == Net::LDAP::LDAP_SUCCESS) {
							$payload = $jsonEntry;
							$payload2 = $entry;
						} else {
							$success = undef;
							print STDERR $entry->ldif()  unless(wantarray);
							
							$payload = [ "Could not modify entry $dn\n".Dumper($updMesg) ];
						}
					} else {
						$success = undef;
						print STDERR $entry->ldif()  unless(wantarray);
						
						$payload = [ "Could not modify entry $dn\n".Dumper($updMesg) ];
					}
				}
			} else {
				# No modification, so give as payload the unmodified $jsonUser
				$payload = $jsonEntry;
			}
		}
	} else {
		push(@{$payload},'The input data to modify must be a hash ref!')  unless(ref($p_entryHash) eq 'HASH');
		push(@{$payload},'The removed keys parameter must be an array ref!')  unless(!defined($p_removedKeys) || ref($p_removedKeys) eq 'ARRAY');
	}
	
	if(wantarray) {
		return ($success,$payload,$payload2);
	} else {
		unless($success) {
			foreach my $err (@{$payload}) {
				Carp::carp($err);
			}
		}
		
		return $success;
	} 
}


# Parameters:
#	username: the RD-Connect username or user e-mail
#	p_userHash: a reference to a hash with the modified user information
#	p_removedKeys: a reference to an array with the removed keys
#	userDN: (OPTIONAL) The DN used as parent of this new ou. If not set,
#		it uses the one read from the configuration file.
# It returns the LDAP entry of the user on success
sub modifyJSONUser($\%;\@$) {
	my $self = shift;
	
	my($username,$p_userHash,$p_removedKeys,$userDN) = @_;
	
	my($success,$payload,$user) = $self->getJSONUser($username,$userDN);
	
	if($success) {
		# $jsonEntry,$entry,$p_entryHash,$p_json2ldap,$validator,$hotchpotchAttribute,$p_ldap_default_attributes
		my $jsonUser = $payload;
		($success,$payload,$user) = $self->modifyJSONEntry(
						$jsonUser,
						$user,
						$p_userHash,
						\%JSON_LDAP_USER_ATTRIBUTES,
						getCASUserValidator(),
						USER_HOTCHPOTCH_ATTRIBUTE,
						\@LDAP_USER_DEFAULT_ATTRIBUTES
					);
	} else {
		push(@{$payload},'Problems fetching the user before modifying it');
	}
	
	if(wantarray) {
		return ($success,$payload,$user);
	} else {
		unless($success) {
			foreach my $err (@{$payload}) {
				Carp::carp($err);
			}
		}
		
		return $success;
	} 
}


# Parameters:
#	username: the RD-Connect username or user e-mail
#	userDN: (OPTIONAL) The DN used as ancestor of this username. If not set,
#		it uses the one read from the configuration file.
# It returns the LDAP entry of the user on success
sub getUser($;$) {
	my $self = shift;
	
	my($username,$userDN) = @_;
	
	$userDN = $self->{'userDN'}  unless(defined($userDN) && length($userDN)>0);
	
	# First, each owner must be found
	my $escaped_username = Net::LDAP::Util::escape_filter_value($username);
	my $searchMesg = $self->{'ldap'}->search(
		'base' => $userDN,
		'filter' => "(&(objectClass=basicRDproperties)(|(uid=$escaped_username)(mail=$escaped_username)))",
		'sizelimit' => 1,
		'scope' => 'sub'
	);
	
	my $success = undef;
	my $payload = [];
	
	if($searchMesg->code() == Net::LDAP::LDAP_SUCCESS) {
		if($searchMesg->count>0) {
			$success = 1;
			# The user entry
			$payload = $searchMesg->entry(0);
		} else {
			push(@{$payload},"No matching user found for $username");
		}
	} else {
		push(@{$payload},"Error while finding user $username\n".Dumper($searchMesg));
	}
	
	if(wantarray) {
		return ($success,$payload);
	} else {
		unless($success) {
			foreach my $err (@{$payload}) {
				Carp::carp($err);
			}
		}
		
		return $success;
	} 
}

# Parameters:
#	username: the RD-Connect username or user e-mail
#	userDN: (OPTIONAL) The DN used as ancestor of this username. If not set,
#		it uses the one read from the configuration file.
# It returns the JSON entry of the user on success in array context
sub getJSONUser($;$) {
	my $self = shift;
	
	my($username,$userDN) = @_;
	
	my($success,$payload) = $self->getUser($username,$userDN);
	
	my $payload2 = undef;
	
	if($success) {
		$payload2 = $payload;
		# The original payload is an LDAP user entry
		$payload = $self->genJSONUsersFromLDAPUsers([$payload2])->[0];
	}
	
	return wantarray ? ($success,$payload,$payload2) : $success;
}

# Parameters:
#	username: the RD-Connect username or user e-mail
#	userDN: (OPTIONAL) The DN used as ancestor of this username. If not set,
#		it uses the one read from the configuration file.
# It returns the JSON entry of the user on success in array context
sub getJSONUserGroups($;$) {
	my $self = shift;
	
	my($username,$userDN) = @_;
	
	my($success,$payload) = $self->getUser($username,$userDN);
	
	if($success) {
		my $user = $payload;
		# The original payload is an LDAP user entry
		my @groupCNs = ();
		$payload = \@groupCNs;
		if($user->exists(USER_MEMBEROF_ATTRIBUTE)) {
			my $p_memberOfs = $user->get_value(USER_MEMBEROF_ATTRIBUTE,'asref' => 1);
			foreach my $memberOf (@{$p_memberOfs}) {
				push(@groupCNs,_getCNFromGroupDN($memberOf));
			}
		}
	}
	
	return wantarray ? ($success,$payload) : $success;
}


# Parameters:
#	username: the RD-Connect username or user e-mail
#	hashedPasswd64: the password, already hashed and represented in the right way
#	userDN: (OPTIONAL) The DN used as parent of this new ou. If not set,
#		it uses the one read from the configuration file.
# It returns the LDAP entry of the user on success (password set and re-enabled)
sub resetUserPassword($$;$) {
	my $self = shift;
	
	my($username,$hashedPasswd64,$userDN) = @_;
	
	$userDN = $self->{'userDN'}  unless(defined($userDN) && length($userDN)>0);
	
	$hashedPasswd64 = $self->encodePassword($hashedPasswd64)  unless(IsEncodedPassword($hashedPasswd64));

	# First, get the entry
	my($success,$payload,$payloadLDAP) = $self->getJSONUser($username,$userDN);
	if($success) {
		my $user = $payloadLDAP;
		my $dn = $user->dn();
		$user->changetype('modify');
		$user->replace(
			'userPassword'	=>	$hashedPasswd64,
			'disabledAccount'	=>	'FALSE',
		);

		my $updMesg = $user->update($self->{'ldap'});
		if($updMesg->code() != Net::LDAP::LDAP_SUCCESS) {
			$success = undef;
			print STDERR $user->ldif()  unless(wantarray);
			
			$payload = [ "Unable to reset user password for $dn\n".Dumper($updMesg) ];
		}
	}
	
	if(wantarray) {
		return ($success,$payload);
	} else {
		unless($success) {
			foreach my $err (@{$payload}) {
				Carp::carp($err);
			}
		}
		
		return $success;
	} 
}

# Parameters:
#	username: the RD-Connect username or user e-mail
#	doEnable: if true, the user is enabled; if false, the user is disabled
#	userDN: (OPTIONAL) The DN used as parent of this new ou. If not set,
#		it uses the one read from the configuration file.
# It returns the LDAP entry of the user on success (user enabled or disabled)
sub enableUser($$;$) {
	my $self = shift;
	
	my($username,$doEnable,$userDN) = @_;
	
	$userDN = $self->{'userDN'}  unless(defined($userDN) && length($userDN)>0);

	# First, get the entry
	my($success,$payload) = $self->getUser($username,$userDN);
	if($success) {
		my $user = $payload;
		my $dn = $user->dn();
		$user->changetype('modify');
		$user->replace(
			'disabledAccount'	=>	($doEnable ? 'FALSE' : 'TRUE'),
		);

		my $updMesg = $user->update($self->{'ldap'});
		if($updMesg->code() != Net::LDAP::LDAP_SUCCESS) {
			$success = undef;
			print STDERR $user->ldif()  unless(wantarray);
			
			$payload = [ "Unable to ".($doEnable ? 'enable' : 'disable')." user $dn\n".Dumper($updMesg) ];
		}
	}
	
	if(wantarray) {
		return ($success,$payload);
	} else {
		unless($success) {
			foreach my $err (@{$payload}) {
				Carp::carp($err);
			}
		}
		
		return $success;
	} 
}

# Parameters:
#	username: the RD-Connect username or user e-mail
#	jpegPhoto: The raw, new photo to be set
#	userDN: (OPTIONAL) The DN used as parent of this new ou. If not set,
#		it uses the one read from the configuration file.
# It returns the LDAP entry of the user on success
sub setUserPhoto($$;$) {
	my $self = shift;
	
	my($username,$jpegPhoto,$userDN) = @_;
	
	$userDN = $self->{'userDN'}  unless(defined($userDN) && length($userDN)>0);

	# First, get the entry
	my($success,$payload) = $self->getUser($username,$userDN);
	if($success) {
		my $user = $payload;
		my $dn = $user->dn();
		$user->changetype('modify');
		$user->replace(
			'jpegPhoto'	=>	$jpegPhoto,
		);

		my $updMesg = $user->update($self->{'ldap'});
		if($updMesg->code() != Net::LDAP::LDAP_SUCCESS) {
			$success = undef;
			print STDERR $user->ldif()  unless(wantarray);
			
			$payload = [ "Unable to set photo for user $dn\n".Dumper($updMesg) ];
		}
	}
	
	if(wantarray) {
		return ($success,$payload);
	} else {
		unless($success) {
			foreach my $err (@{$payload}) {
				Carp::carp($err);
			}
		}
		
		return $success;
	} 
}


# Parameters:
#	userDN: (OPTIONAL) The DN used as parent of all the users. If not set,
#		it uses the one read from the configuration file.
sub listUsers(;$) {
	my $self = shift;
	
	my($userDN) = @_;
	
	$userDN = $self->{'userDN'}  unless(defined($userDN) && length($userDN)>0);
	
	# First, the ou must be found
	my $searchMesg = $self->{'ldap'}->search(
		'base' => $userDN,
		'filter' => '(objectClass=inetOrgPerson)',
		'scope' => 'children'
	);
	
	my $success = $searchMesg->code() == Net::LDAP::LDAP_SUCCESS;
	my $payload;
	if($success) {
		$payload = [ $searchMesg->entries ];
	} else {
		$payload = [ "Error while finding users\n".Dumper($searchMesg) ];
	}
	
	return ($success,$payload);
}

# Parameters:
#	userDN: (OPTIONAL) The DN used as parent of all the users. If not set,
#		it uses the one read from the configuration file.
sub listEnabledUsers(;$) {
	my $self = shift;
	
	my($userDN) = @_;
	
	$userDN = $self->{'userDN'}  unless(defined($userDN) && length($userDN)>0);
	
	# First, the ou must be found
	my $searchMesg = $self->{'ldap'}->search(
		'base' => $userDN,
		'filter' => '(&(objectClass=inetOrgPerson)(disabledAccount=FALSE))',
		'scope' => 'children'
	);
	
	my $success = $searchMesg->code() == Net::LDAP::LDAP_SUCCESS;
	my $payload;
	if($success) {
		$payload = [ $searchMesg->entries ];
	} else {
		$payload = [ "Error while finding users\n".Dumper($searchMesg) ];
	}
	
	return ($success,$payload);
}

# Parameters:
#	userDN: (OPTIONAL) The DN used as parent of all the users. If not set,
#		it uses the one read from the configuration file.
sub listJSONUsers(;$) {
	my $self = shift;
	
	my($userDN) = @_;
	
	my($success,$payload) = $self->listUsers($userDN);
	
	if($success) {
		$payload = $self->genJSONUsersFromLDAPUsers($payload);
	}
	
	return ($success,$payload);
}

# Parameters:
#	userDN: (OPTIONAL) The DN used as parent of all the users. If not set,
#		it uses the one read from the configuration file.
sub listJSONEnabledUsers(;$) {
	my $self = shift;
	
	my($userDN) = @_;
	
	my($success,$payload) = $self->listEnabledUsers($userDN);
	
	if($success) {
		$payload = $self->genJSONEnabledUsersFromLDAPUsers($payload);
	}
	
	return ($success,$payload);
}

my @LDAP_PEOPLE_OU_DEFAULT_ATTRIBUTES = (
	'objectClass'	=>	 ['extensibleObject','organizationalUnit'],
);

# Parameters:
#	ou: The short, organizational unit name, which will hang on userDN
#	description: The description of the new organizational unit
#	userDN: (OPTIONAL) The DN used as parent of this new ou. If not set,
#		it uses the one read from the configuration file.
#	doReplace: (OPTIONAL) If true, the entry is an update
sub createPeopleOU($$;$$) {
	my $self = shift;
	
	my($ou,$description,$userDN,$doReplace) = @_;
	
	$userDN = $self->{'userDN'}  unless(defined($userDN) && length($userDN)>0);
	
	my $entry = Net::LDAP::Entry->new();
	$entry->changetype('modify')  if($doReplace);
	my $dn = join(',','ou='.Net::LDAP::Util::escape_dn_value($ou),$userDN);
	$entry->dn($dn);
	$entry->add(
		'ou'	=>	$ou,
		'description'	=>	$description,
		@LDAP_PEOPLE_OU_DEFAULT_ATTRIBUTES
	);
	
	my $updMesg = $entry->update($self->{'ldap'});
	
	if($updMesg->code() != Net::LDAP::LDAP_SUCCESS) {
		print STDERR $entry->ldif();
		
		Carp::carp("Unable to create organizational unit $dn (does the organizational unit already exist?)\n".Dumper($updMesg));
	}
	return $updMesg->code() == Net::LDAP::LDAP_SUCCESS;
}

# Parameters:
#	p_peopleOUArray: a reference to a hash or an array of hashes with the required keys needed to create new organizational units
#	doReplace: if true, the entry is an update
sub createExtPeopleOU(\[%@];$) {
	my $self = shift;
	my($p_peopleOUArray,$doReplace) = @_;
	
	# $p_entryArray,$m_getDN,$m_normalizePKJSON,$validator,$p_json2ldap,$hotchpotchAttribute,$p_ldap_default_attributes,$doReplace
	return $self->createLDAPFromJSON(
				$p_peopleOUArray,
				\&_getPeopleOUDNFromJSON,
				undef,
				getCASouValidator(),
				undef,
				\%JSON_LDAP_OU_ATTRIBUTES,
				undef,
				\@LDAP_PEOPLE_OU_DEFAULT_ATTRIBUTES,
				$doReplace
			);
}

# Parameters:
#	ou: the RD-Connect organizational unit
#	userDN: (OPTIONAL) The DN used as ancestor of this username. If not set,
#		it uses the one read from the configuration file.
# It returns the LDAP entry of the user on success
sub getPeopleOU($;$) {
	my $self = shift;
	
	my($ou,$userDN) = @_;
	
	$userDN = $self->{'userDN'}  unless(defined($userDN) && length($userDN)>0);
	
	# First, each owner must be found
	my $escaped_ou = Net::LDAP::Util::escape_filter_value($ou);
	my $searchMesg = $self->{'ldap'}->search(
		'base' => $userDN,
		'filter' => "(&(objectClass=organizationalUnit)(ou=$escaped_ou))",
		'sizelimit' => 1,
		'scope' => 'sub'
	);
	
	my $success = undef;
	my $payload = [];
	
	if($searchMesg->code() == Net::LDAP::LDAP_SUCCESS) {
		if($searchMesg->count>0) {
			$success = 1;
			# The ou entry
			$payload = $searchMesg->entry(0);
		} else {
			push(@{$payload},"No matching organizational unit found for $ou");
		}
	} else {
		push(@{$payload},"Error while finding organizational unit $ou\n".Dumper($searchMesg));
	}
	
	if(wantarray) {
		return ($success,$payload);
	} else {
		unless($success) {
			foreach my $err (@{$payload}) {
				Carp::carp($err);
			}
		}
		
		return $success;
	} 
}

# Parameters:
#	ou: the RD-Connect organizational unit
#	userDN: (OPTIONAL) The DN used as ancestor of this organizational
#		 unit. If not set, it uses the one read from the configuration file.
# It returns the JSON entry of the organizational unit on success in array context
sub getJSONPeopleOU($;$) {
	my $self = shift;
	
	my($ou,$userDN) = @_;
	
	my($success,$payload) = $self->getPeopleOU($ou,$userDN);
	
	my $payload2 = undef;
	
	if($success) {
		$payload2 = $payload;
		# The original payload is an LDAP organizational unit entry
		$payload = $self->genJSONouFromLDAPou([$payload2])->[0];
	}
	
	return wantarray ? ($success,$payload,$payload2) : $success;
}

# Parameters:
#	ou: the RD-Connect organizational unit
#	p_peopleOUHash: a reference to a hash with the modified organizational unit information
#	p_removedKeys: a reference to an array with the removed keys
#	userDN: (OPTIONAL) The DN used as parent of this new ou. If not set,
#		it uses the one read from the configuration file.
# It returns the LDAP entry of the user on success
sub modifyJSONPeopleOU($\%;\@$) {
	my $self = shift;
	
	my($ou,$p_peopleOUHash,$p_removedKeys,$userDN) = @_;
	
	my($success,$payload,$peopleOU) = $self->getJSONPeopleOU($ou,$userDN);
	
	if($success) {
		# $jsonEntry,$entry,$p_entryHash,$p_json2ldap,$validator,$hotchpotchAttribute,$p_ldap_default_attributes
		my $jsonPeopleOU = $payload;
		($success,$payload,$peopleOU) = $self->modifyJSONEntry(
							$jsonPeopleOU,
							$peopleOU,
							$p_peopleOUHash,
							\%JSON_LDAP_OU_ATTRIBUTES,
							getCASouValidator(),
							undef,
							\@LDAP_PEOPLE_OU_DEFAULT_ATTRIBUTES
						);
	} else {
		push(@{$payload},'Problems fetching the organizational unit before modifying it');
	}
	
	if(wantarray) {
		return ($success,$payload,$peopleOU);
	} else {
		unless($success) {
			foreach my $err (@{$payload}) {
				Carp::carp($err);
			}
		}
		
		return $success;
	} 
}


# Parameters:
#	ou: the RD-Connect organizational unit
#	jpegPhoto: The raw, new photo to be set
#	userDN: (OPTIONAL) The DN used as parent of this new ou. If not set,
#		it uses the one read from the configuration file.
# It returns the LDAP entry of the user on success (user enabled or disabled)
sub setPeopleOUPhoto($$;$) {
	my $self = shift;
	
	my($ou,$jpegPhoto,$userDN) = @_;
	
	$userDN = $self->{'userDN'}  unless(defined($userDN) && length($userDN)>0);

	# First, get the entry
	my($success,$payload) = $self->getPeopleOU($ou,$userDN);
	if($success) {
		my $organizationalUnit = $payload;
		my $dn = $organizationalUnit->dn();
		$organizationalUnit->changetype('modify');
		$organizationalUnit->replace(
			'jpegPhoto'	=>	$jpegPhoto,
			@LDAP_PEOPLE_OU_DEFAULT_ATTRIBUTES
		);

		my $updMesg = $organizationalUnit->update($self->{'ldap'});
		if($updMesg->code() != Net::LDAP::LDAP_SUCCESS) {
			$success = undef;
			print STDERR $organizationalUnit->ldif()  unless(wantarray);
			
			$payload = [ "Unable to set photo for organizational unit $dn\n".Dumper($updMesg) ];
		}
	}
	
	if(wantarray) {
		return ($success,$payload);
	} else {
		unless($success) {
			foreach my $err (@{$payload}) {
				Carp::carp($err);
			}
		}
		
		return $success;
	} 
}

# Parameters:
#	userDN: (OPTIONAL) The DN used as parent of all the ou. If not set,
#		it uses the one read from the configuration file.
sub listPeopleOU(;$) {
	my $self = shift;
	
	my($userDN) = @_;
	
	$userDN = $self->{'userDN'}  unless(defined($userDN) && length($userDN)>0);
	
	# First, the ou must be found
	my $searchMesg = $self->{'ldap'}->search(
		'base' => $userDN,
		'filter' => '(objectClass=organizationalUnit)',
		'scope' => 'children'
	);
	
	my $success = $searchMesg->code() == Net::LDAP::LDAP_SUCCESS;
	my $payload;
	
	if($success) {
		$payload = [ $searchMesg->entries ];
	} else {
		$payload = [ "Error while finding people OUs\n".Dumper($searchMesg) ];
	}
	
	return ($success,$payload);
}

# Parameters:
#	userDN: (OPTIONAL) The DN used as parent of all the users. If not set,
#		it uses the one read from the configuration file.
sub listJSONPeopleOU(;$) {
	my $self = shift;
	
	my($userDN) = @_;
	
	my($success,$payload) = $self->listPeopleOU($userDN);
	
	if($success) {
		$payload = $self->genJSONouFromLDAPou($payload);
	}
	
	return ($success,$payload);
}

# Parameters:
#	ou: The short, organizational unit name, which hangs on userDN
#	userDN: (OPTIONAL) The DN used as parent of all the users. If not set,
#		it uses the one read from the configuration file.
sub listPeopleOUUsers($;$) {
	my $self = shift;
	
	my($ou,$userDN) = @_;
	
	$userDN = $self->{'userDN'}  unless(defined($userDN) && length($userDN)>0);
	my $dn = join(',','ou='.Net::LDAP::Util::escape_dn_value($ou),$userDN);
	
	# First, the ou must be found
	my $searchMesg = $self->{'ldap'}->search(
		'base' => $dn,
		'filter' => '(objectClass=inetOrgPerson)',
		'scope' => 'children'
	);
	
	my $success = $searchMesg->code() == Net::LDAP::LDAP_SUCCESS;
	my $payload;
	if($success) {
		$payload = [ $searchMesg->entries ];
	} else {
		$payload = [ "Error while finding users\n".Dumper($searchMesg) ];
	}
	
	return ($success,$payload);
}

# Parameters:
#	ou: The short, organizational unit name, which hangs on userDN
#	userDN: (OPTIONAL) The DN used as parent of all the users. If not set,
#		it uses the one read from the configuration file.
sub listJSONPeopleOUUsers($;$) {
	my $self = shift;
	
	my($ou,$userDN) = @_;
	
	my($success,$payload) = $self->listPeopleOUUsers($ou,$userDN);
	
	if($success) {
		$payload = $self->genJSONUsersFromLDAPUsers($payload);
	}
	
	return ($success,$payload);
}

# Parameters:
#	username: the RD-Connect username or user e-mail
#	ou: The short, organizational unit name, which is the destination of the username
#	baseUserDN: (OPTIONAL) The DN used as ancestor of the user and ou entries. If not set,
#		it uses the one read from the configuration file.
sub moveUserToPeopleOU($$;$) {
	my $self = shift;
	
	my($username,$ou,$baseUserDN)=@_;
	
	$baseUserDN = $self->{'userDN'}  unless(defined($baseUserDN) && length($baseUserDN)>0);
	
	my $parentDN = $self->{'parentDN'};
	
	# Is the user found?
	my($success,$payload) = $self->getUser($username,$baseUserDN);
	
	my $user;
	my $oldUserDN;
	if($success) {
		$user = $payload;
		$oldUserDN = $user->dn();
		
		# Don
		if($user->exists('cn')) {
			# Is the ou found?
			($success,$payload) = $self->getPeopleOU($ou,$baseUserDN);
		} else {
			$success = undef;
			$payload = [ "Missing cn attribute for user $oldUserDN" ];
		}
	}
	my $ou;
	my $newUserDN;
	my @refEntries = ();
	my $escaped_userCN;
	if($success) {
		$ou = $payload;
		$payload = [];

		my $e_ouDN = Net::LDAP::Util::ldap_explode_dn($ou->dn(),@LDAP_UTIL_SERIALIZATION_PARAMS);
		my $userCN = $user->get_value('cn');
		unshift(@{$e_ouDN},{'cn' => $userCN});
		$newUserDN = Net::LDAP::Util::canonical_dn($e_ouDN,@LDAP_UTIL_SERIALIZATION_PARAMS);
	
		# Is the new name in use?
		$success = undef;
		if($self->existsDN($newUserDN)) {
			push(@{$payload},"$oldUserDN cannot be moved to $newUserDN, as it already exists");
		} else {
			# Generating the escaped userCN
			$escaped_userCN = Net::LDAP::Util::escape_filter_value($userCN);
			
			# Fetching the entries referring to the user
			my $escaped_oldUserDn = Net::LDAP::Util::escape_filter_value($oldUserDN);
			my $refSearchMesg = $self->{'ldap'}->search(
				'base'	=> $parentDN,
				'filter' => "(:distinguishedNameMatch:=$escaped_oldUserDn)",
				'scope' => 'sub',
			);
			
			if($refSearchMesg->code() == Net::LDAP::LDAP_SUCCESS) {
				@refEntries = $refSearchMesg->entries();
				$success = 1;
			} else {
				push(@{$payload},"Error while finding members of $oldUserDN\n".Dumper($refSearchMesg));
			}
		}
	}
	
	if($success) {
		# Now, time to move the user (and change all the references to her/him)
		$user->changetype("moddn");
		# The old entry will be erased later, when all the updates are in place
		$user->add(
			"deleteoldrdn" => 1,
			"newsuperior" => $ou->dn(),
			"newrdn" => "cn=$escaped_userCN"
		);
		
		# Now, batch updates!
		my $updMesg = $user->update($self->{'ldap'});
		if($updMesg->code() == Net::LDAP::LDAP_SUCCESS) {
			foreach my $refEntry (@refEntries) {
				my @replacements = ();
				foreach my $attr ($refEntry->attributes()) {
					my $p_members = $refEntry->get_value($attr,"asref" => 1);
					my $didMatch = undef;
					my @newValues = ();
					foreach my $member (@{$p_members}) {
						my $val;
						if($member eq $oldUserDN) {
							$val = $newUserDN;
							$didMatch = 1;
						} else {
							$val = $member;
						}
						
						push(@newValues,$val);
						#print "ENTRY\n$oldDn\n$newDn\n$member\n$val\n";
					}
					
					if($didMatch) {
						push(@replacements, $attr => \@newValues);
					}
				}
				
				if(scalar(@replacements) > 0) {
					$refEntry->changetype("modify");
					$refEntry->replace(@replacements);
					my $refUpdMesg = $refEntry->update($self->{'ldap'});
					if($refUpdMesg->code() != Net::LDAP::LDAP_SUCCESS) {
						$success = undef;
						print STDERR $refEntry->ldif()  unless(wantarray);
						
						my $refDn = $refEntry->dn();
						push(@{$payload}, "Could not update entry $refDn\n".Dumper($refUpdMesg) );
						last;
					}
				}
			}
		} else {
			$success = undef;
			print STDERR $user->ldif()  unless(wantarray);
			
			push(@{$payload}, "Could not move entry $oldUserDN\n".Dumper($updMesg) );
		}
	}
	
	if(wantarray) {
		return ($success,$payload);
	} else {
		unless($success) {
			foreach my $err (@{$payload}) {
				Carp::carp($err);
			}
		}
		
		return $success;
	} 
}

# Parameters:
#	ou: the RD-Connect organizational unit
#	userDN: (OPTIONAL) The DN used as ancestor of this username. If not set,
#		it uses the one read from the configuration file.
sub removePeopleOU($;$) {
	my $self = shift;
	
	my($ou,$userDN) = @_;
	
	$userDN = $self->{'userDN'}  unless(defined($userDN) && length($userDN)>0);
	
	# Is the OU found?
	my($success,$payload) = $self->getPeopleOU($ou,$userDN);
	
	if($success) {
		my $ou = $payload;
		$payload = [];
		
		# Now, erasing the OU (this operation CANNOT BE UNDONE!)
		my $delMesg = $ou->delete()->update($self->{'ldap'});
		if($delMesg->code() != Net::LDAP::LDAP_SUCCESS) {
			$success = undef;
			push(@{$payload},"Error while removing $ou from $userDN\n".Dumper($delMesg));
		}
	}
	
	if(wantarray) {
		return ($success,$payload);
	} else {
		unless($success) {
			foreach my $err (@{$payload}) {
				Carp::carp($err);
			}
		}
		
		return $success;
	} 
}



my @LDAP_GROUP_DEFAULT_ATTRIBUTES = (
	'objectClass'	=>	[ 'groupOfNames' ]
);

# Parameters:
#	cn: The short, common name, which will hang on groupDN
#	description: The description of the new groupOfNames
#	p_ownerUIDs: The uid(s) of the owner and first member of this groupOfNames.
#	userDN: (OPTIONAL) The DN used as parent of all the ou. If not set,
#		it uses the one read from the configuration file.
#	groupDN: (OPTIONAL) The DN used as parent of this new groupOfNames.
#		If not set, it uses the one read from the configuration file.
#	doReplace: (OPTIONAL) If true, the entry is an update
sub createGroup($$$;$$) {
	my $self = shift;
	
	my($cn,$description,$p_ownerUIDs,$userDN,$groupDN,$doReplace)=@_;
	
	$userDN = $self->{'userDN'}  unless(defined($userDN) && length($userDN)>0);
	$groupDN = $self->{'groupDN'}  unless(defined($groupDN) && length($groupDN)>0);
	
	$p_ownerUIDs = [ $p_ownerUIDs ]  unless(ref($p_ownerUIDs) eq 'ARRAY');
	
	my @owners = ();
	my @ownersDN = ();
	
	# First, each owner must be found
	my $success = 1;
	my $payload = [];
	foreach my $ownerUID (@{$p_ownerUIDs}) {
		# The owner entry
		my($partialSuccess,$owner) = $self->getUser($ownerUID,$userDN);
		
		if($partialSuccess) {
			push(@owners,$owner);
			push(@ownersDN,$owner->dn());
		} else {
			# And all the errors must be gathered
			$success = undef;
			push(@{$payload},@{$owner});
		}
	}
	
	if($success) {
		# Now, the group of names new entry
		my $entry = Net::LDAP::Entry->new();
		$entry->changetype('modify')  if($doReplace);
		my $dn = join(',','cn='.Net::LDAP::Util::escape_dn_value($cn),$groupDN);
		$entry->dn($dn);
		$entry->add(
			'cn'	=>	$cn,
			'description'	=>	$description,
			'owner'	=>	\@ownersDN,
			'member'	=>	\@ownersDN,
			@LDAP_GROUP_DEFAULT_ATTRIBUTES
		);
		
		my $updMesg = $entry->update($self->{'ldap'});
		
		if($updMesg->code() == Net::LDAP::LDAP_SUCCESS) {
			# Second step, for all the owners, point back
			foreach my $owner (@owners) {
				# And, at last, add the dn to the memberOf list
				$owner->changetype('modify');
				$owner->add(USER_MEMBEROF_ATTRIBUTE() => $dn);
				
				$updMesg = $owner->update($self->{'ldap'});
				
				if($updMesg->code() != Net::LDAP::LDAP_SUCCESS) {
					$success = undef;
					print STDERR $owner->ldif()  unless(wantarray);
					
					push(@{$payload},"Unable to add memberOf $dn to ".$owner->dn()."\n".Dumper($updMesg));
					
					last;
				}
			}
		} else {
			$success = undef;
			print STDERR $entry->ldif()  unless(wantarray);
			
			push(@{$payload},"Unable to create group of names $dn (does the group of names already exist?)\n".Dumper($updMesg));
		}
	}
	
	if(wantarray) {
		return ($success,$payload);
	} else {
		unless($success) {
			foreach my $err (@{$payload}) {
				Carp::carp($err);
			}
		}
		
		return $success;
	} 
}

# Parameters:
#	p_groupArray: a reference to a hash or an array of hashes with the required keys needed to create new groups
#	doReplace: (OPTIONAL) if true, the entry is an update
sub createExtGroup(\[%@];$) {
	my $self = shift;
	my($p_groupArray,$doReplace) = @_;
	
	$p_groupArray = [ $p_groupArray ]  unless(ref($p_groupArray) eq 'ARRAY');
	
	my $success;
	my $payload = [];
	foreach my $p_groupEntry (@{$p_groupArray}) {
		# $p_entryArray,$m_getDN,$m_normalizePKJSON,$validator,$p_json2ldap,$hotchpotchAttribute,$p_ldap_default_attributes,$doReplace
		
		# Curating the entry
		if(exists($p_groupEntry->{'owner'})) {
			if(!exists($p_groupEntry->{'members'})) {
				$p_groupEntry->{'members'} = $p_groupEntry->{'owner'};
			} else {
				# Find the owners in the members list, and initially add them
				my %memberHash = map { $_ => undef } @{$p_groupEntry->{'members'}};
				foreach my $owner (@{$p_groupEntry->{'owner'}}) {
					push(@{$p_groupEntry->{'members'}},$owner)  unless(exists($memberHash{$owner}));
				}
			}
		}
		
		my $partialPayload = undef;
		($success,$partialPayload) = $self->createLDAPFromJSON(
					$p_groupEntry,
					\&_getGroupDNFromJSON,
					undef,
					getCASGroupValidator(),
					undef,
					\%JSON_LDAP_GROUP_ATTRIBUTES,
					undef,
					\@LDAP_GROUP_DEFAULT_ATTRIBUTES,
					$doReplace
				);
		
		last  unless($success);
		
		# The entry was created. Now, add all the members back!
		# The dn of the entry
		my $jsonGroupEntry = $partialPayload->[0];
		my $dn = _getGroupDNFromJSON($self,%{$jsonGroupEntry});
		
		# Gathering the members
		foreach my $memberUID (@{$jsonGroupEntry->{'members'}}) {
			# The member entry
			my($partialSuccess,$member) = $self->getUser($memberUID);
			
			if($partialSuccess) {
				# Second step, point back to the groupOfNames
				$member->changetype('modify');
				$member->add(USER_MEMBEROF_ATTRIBUTE() => $dn);
				
				my $updMesg = $member->update($self->{'ldap'});
				
				if($updMesg->code() != Net::LDAP::LDAP_SUCCESS) {
					$success = undef;
					print STDERR $member->ldif()  unless(wantarray);
					
					push(@{$payload},"Unable to add memberOf $dn to ".$member->dn()."\n".Dumper($updMesg));
				}
			} else {
				# And all the errors must be gathered
				$success = undef;
				push(@{$payload},@{$member});
			}
		}
		
		last  unless($success);
	}
	
	if(wantarray) {
		return ($success,$payload);
	} else {
		unless($success) {
			foreach my $err (@{$payload}) {
				Carp::carp($err);
			}
		}
		
		return $success;
	} 
}

# Parameters:
#	groupCN: The cn of the groupOfNames to find
#	groupDN: (OPTIONAL) The DN used as parent of this new groupOfNames.
#		If not set, it uses the one read from the configuration file.
# It returns the LDAP entry of the group on success
sub getGroup($;$) {
	my $self = shift;
	
	my($groupCN,$groupDN)=@_;
	
	$groupDN = $self->{'groupDN'}  unless(defined($groupDN) && length($groupDN)>0);
	
	my $escaped_groupCN = Net::LDAP::Util::escape_filter_value($groupCN);
	my $searchMesg = $self->{'ldap'}->search(
		'base' => $groupDN,
		'filter' => "(&(objectClass=groupOfNames)(cn=$escaped_groupCN))",
		'sizelimit' => 1,
		'scope' => 'sub'
	);
	
	my $success = undef;
	my $payload = [];
	
	if($searchMesg->code() == Net::LDAP::LDAP_SUCCESS) {
		if($searchMesg->count>0) {
			$success = 1;
			# The group entry
			$payload = $searchMesg->entry(0);
		} else {
			push(@{$payload},"No matching group found for $groupCN");
		}
	} else {
		push(@{$payload},"Error while finding group $groupCN\n".Dumper($searchMesg));
	}
	
	if(wantarray) {
		return ($success,$payload);
	} else {
		unless($success) {
			foreach my $err (@{$payload}) {
				Carp::carp($err);
			}
		}
		
		return $success;
	} 
}

# Parameters:
#	groupCN: the RD-Connect group
#	groupDN: (OPTIONAL) The DN used as ancestor of this group.
#		 If not set, it uses the one read from the configuration file.
# It returns the JSON entry of the group on success in array context
sub getJSONGroup($;$) {
	my $self = shift;
	
	my($groupCN,$groupDN) = @_;
	
	my($success,$payload) = $self->getGroup($groupCN,$groupDN);
	
	my $payload2 = undef;
	
	if($success) {
		$payload2 = $payload;
		# The original payload is an LDAP groupOfNames entry
		$payload = $self->genJSONGroupsFromLDAPGroups([$payload2])->[0];
	}
	
	return wantarray ? ($success,$payload,$payload2) : $success;
}

# Parameters:
#	groupCN: The cn of the groupOfNames to find
#	usersFacet: The facet where the users are listed
#	groupDN: (OPTIONAL) The DN used as parent of this new groupOfNames.
#		If not set, it uses the one read from the configuration file.
# It returns a reference to the array of LDAP entries corresponding to the group members on success
sub getGroupUsersFacet($$;$) {
	my $self = shift;
	
	my($groupCN,$usersFacet,$groupDN)=@_;
	
	$groupDN = $self->{'groupDN'}  unless(defined($groupDN) && length($groupDN)>0);
	
	my($success,$group) = $self->getGroup($groupCN,$groupDN);
	return undef  unless($success);
	
	my $payload = [];
	my @users = ();
	my $p_userDNs = $group->get_value($usersFacet,'asref' => 1);
	foreach my $userDN (@{$p_userDNs}) {
		my $searchMesg = $self->{'ldap'}->search(
			'base' => $userDN,
			'filter' => '(objectClass=*)',
			'sizelimit' => 1,
			'scope' => 'base'
		);
		
		if($searchMesg->code() == Net::LDAP::LDAP_SUCCESS) {
			push(@users,$searchMesg->entry(0));
		} else {
			$success = undef;
			push(@{$payload},"Error while finding user $userDN\n".Dumper($searchMesg));
			
			next;
		}
	}
	
	$payload = \@users  if($success);
	
	return ($success,$payload);
}

# Parameters:
#	groupCN: The cn of the groupOfNames to find
#	groupDN: (OPTIONAL) The DN used as parent of this new groupOfNames.
#		If not set, it uses the one read from the configuration file.
# It returns a reference to the array of LDAP entries corresponding to the group members on success
sub getGroupMembers($;$) {
	my $self = shift;
	
	my($groupCN,$groupDN)=@_;
	
	return $self->getGroupUsersFacet($groupCN,'member',$groupDN);
}

# Parameters:
#	groupCN: The cn of the groupOfNames to find
#	groupDN: (OPTIONAL) The DN used as parent of this new groupOfNames.
#		If not set, it uses the one read from the configuration file.
# It returns a reference to the array of LDAP entries corresponding to the group members on success
sub getJSONGroupMembers($;$) {
	my $self = shift;
	
	my($groupCN,$groupDN)=@_;
	
	my($success,$payload) = $self->getGroupMembers($groupCN,$groupDN);
	
	if($success) {
		$payload = $self->genJSONUsersFromLDAPUsers($payload);
	}
	
	return ($success,$payload);
}

# Parameters:
#	groupCN: The cn of the groupOfNames to find
#	groupDN: (OPTIONAL) The DN used as parent of this new groupOfNames.
#		If not set, it uses the one read from the configuration file.
# It returns a reference to the array of LDAP entries corresponding to the group owners on success
sub getGroupOwners($;$) {
	my $self = shift;
	
	my($groupCN,$groupDN)=@_;
	
	return $self->getGroupUsersFacet($groupCN,'owner',$groupDN);
}

# Parameters:
#	groupCN: The cn of the groupOfNames to find
#	groupDN: (OPTIONAL) The DN used as parent of this new groupOfNames.
#		If not set, it uses the one read from the configuration file.
# It returns a reference to the array of LDAP entries corresponding to the group owners on success
sub getJSONGroupOwners($;$) {
	my $self = shift;
	
	my($groupCN,$groupDN)=@_;
	
	my($success,$payload) = $self->getGroupOwners($groupCN,$groupDN);
	
	if($success) {
		$payload = $self->genJSONUsersFromLDAPUsers($payload);
	}
	
	return ($success,$payload);
}

# Parameters:
#	cn: the RD-Connect group
#	p_groupHash: a reference to a hash with the modified organizational unit information
#	p_removedKeys: a reference to an array with the removed keys
#	groupDN: (OPTIONAL) The DN used as parent of this new ou. If not set,
#		it uses the one read from the configuration file.
# It returns the LDAP entry of the user on success
sub modifyJSONGroup($\%;\@$) {
	my $self = shift;
	
	my($groupCN,$p_groupHash,$p_removedKeys,$groupDN) = @_;
	
	my($success,$payload,$group) = $self->getJSONGroup($groupCN,$groupDN);
	
	if($success) {
		# $jsonEntry,$entry,$p_entryHash,$p_json2ldap,$validator,$hotchpotchAttribute,$p_ldap_default_attributes
		my $jsonGroup = $payload;
		($success,$payload,$group) = $self->modifyJSONEntry(
							$jsonGroup,
							$group,
							$p_groupHash,
							\%JSON_LDAP_GROUP_ATTRIBUTES,
							getCASGroupValidator(),
							undef,
							\@LDAP_GROUP_DEFAULT_ATTRIBUTES
						);
	} else {
		push(@{$payload},'Problems fetching the group before modifying it');
	}
	
	if(wantarray) {
		return ($success,$payload,$group);
	} else {
		unless($success) {
			foreach my $err (@{$payload}) {
				Carp::carp($err);
			}
		}
		
		return $success;
	} 
}

# Parameters:
#	groupDN: (OPTIONAL) The DN used as parent of all the groups. If not set,
#		it uses the one read from the configuration file.
sub listGroups(;$) {
	my $self = shift;
	
	my($groupDN) = @_;
	
	$groupDN = $self->{'groupDN'}  unless(defined($groupDN) && length($groupDN)>0);
	
	# First, the ou must be found
	my $searchMesg = $self->{'ldap'}->search(
		'base' => $groupDN,
		'filter' => '(objectClass=groupOfNames)',
		'scope' => 'children'
	);
	
	my $success = $searchMesg->code() == Net::LDAP::LDAP_SUCCESS;
	my $payload;
	
	if($success) {
		$payload = [ $searchMesg->entries ];
	} else {
		$payload = [ "Error while finding groups\n".Dumper($searchMesg) ];
	}
	
	return ($success,$payload);
}

# Parameters:
#	groupDN: (OPTIONAL) The DN used as parent of all the groups. If not set,
#		it uses the one read from the configuration file.
sub listJSONGroups(;$) {
	my $self = shift;
	
	my($groupDN) = @_;
	
	my($success,$payload) = $self->listGroups($groupDN);
	
	if($success) {
		$payload = $self->genJSONGroupsFromLDAPGroups($payload);
	}
	
	return ($success,$payload);
}


# Parameters:
#	userUID: The uid of the user to be added to the groupOfNames, or an array of them.
#	isOwner: Is this one becoming an owner?
#	p_groupCN: The cn(s) of the groupOfNames where the user must be added
#	userDN: (OPTIONAL) The DN used as parent of all the ou. If not set,
#		it uses the one read from the configuration file.
#	groupDN: (OPTIONAL) The DN used as parent of this new groupOfNames.
#		If not set, it uses the one read from the configuration file.
sub addUserToGroup($$$;$$) {
	my $self = shift;
	
	my($userUID,$isOwner,$p_groupCN,$userDN,$groupDN)=@_;
	my $p_userUIDs = (ref($userUID) eq 'ARRAY') ? $userUID : [ $userUID ];
	
	$userDN = $self->{'userDN'}  unless(defined($userDN) && length($userDN)>0);
	$groupDN = $self->{'groupDN'}  unless(defined($groupDN) && length($groupDN)>0);
	
	$p_groupCN = [ $p_groupCN ]  unless(ref($p_groupCN) eq 'ARRAY');
	
	my $success = undef;
	my $payload = undef;
	my @users = ();
	# First, all the user(s) must be found
	foreach my $userUID (@{$p_userUIDs}) {
		# Is the user already a Net::LDAP::Entry????
		if(Scalar::Util::blessed($userUID) && $userUID->isa('Net::LDAP::Entry')) {
			$success = 1;
			push(@users,$userUID);
		} else {
			($success, $payload) = $self->getUser($userUID,$userDN);
			
			last  unless($success);
			
			# Saving the LDAP user entries for further usage
			push(@users,$payload);
		}
	}
	#if($success && $payload->get_value('disabledAccount') eq 'TRUE') {
	#	$success = undef;
	#	$payload = [ 'Cannot modify a disabled user' ];
	#}
	
	# Then, let's add the users one by one
	if($success && scalar(@users) > 0) {
		foreach my $user (@users) {
			$payload = [];
			
			my @newGroups = ();
			
			ADD_USER_GROUPCN:
			foreach my $groupCN (@{$p_groupCN}) {
				# Second, each group of names must be found
				my($partialSuccess,$group) = $self->getGroup($groupCN,$groupDN);
				
				unless($partialSuccess) {
					$success = undef;
					push(@{$payload},@{$group});
					next;
				}
				
				# Is the user already in the group?
				my $isMember = 1;
				my $p_members = $group->get_value('member', 'asref' => 1);
				foreach my $member (@{$p_members}) {
					if($member eq $user->dn()) {
						if($isOwner) {
							$isMember = undef;
						} else {
							next ADD_USER_GROUPCN;
						}
					}
				}
				
				if($isOwner) {
					my $p_owners = $group->get_value('owner', 'asref' => 1);
					foreach my $owner (@{$p_owners}) {
						next ADD_USER_GROUPCN  if($owner eq $user->dn());
					}
				}
				
				push(@newGroups,[$group,$isMember,$isOwner]);
			}
			
			if($success && scalar(@newGroups) > 0) {
				my @newGroupDNs = ();
				foreach my $p_gDesc (@newGroups) {
					my($group,$isMember,$isOwner) = @{$p_gDesc};
					# Now, add the user dn to the group's member list
					$group->changetype('modify');
					$group->add('member' => $user->dn())  if($isMember);
					$group->add('owner' => $user->dn())  if($isOwner);
					
					my $updMesg = $group->update($self->{'ldap'});
					
					if($updMesg->code() != Net::LDAP::LDAP_SUCCESS) {
						$success = undef;
						print STDERR $group->ldif()  unless(wantarray);
						
						push(@{$payload},"Unable to add ".($isOwner?"owner":"member")." ".$user->dn()." to ".$group->dn()."\n".Dumper($updMesg));
						last;
					}
					
					# Add only in case of new membership of a group
					push(@newGroupDNs,$group->dn())  if($isMember);
				}
				
				if($success && scalar(@newGroupDNs) > 0) {
					@newGroups = ();
					
					# And, at last, add the group dn to the user's memberOf list
					$user->changetype('modify');
					$user->add(USER_MEMBEROF_ATTRIBUTE() => \@newGroupDNs);
					
					my $updMesg = $user->update($self->{'ldap'});
					
					if($updMesg->code() != Net::LDAP::LDAP_SUCCESS) {
						$success = undef;
						print STDERR $user->ldif()  unless(wantarray);
						
						push(@{$payload},"Unable to add memberOf ".join(',',@newGroupDNs)." to ".$user->dn()."\n".Dumper($updMesg));
					}
				}
			}
			
			last  unless($success);
		}
	}
	
	if(wantarray) {
		return ($success,$payload);
	} else {
		unless($success) {
			foreach my $err (@{$payload}) {
				Carp::carp($err);
			}
		}
		
		return $success;
	} 
}

# Parameters:
#	userUID: The uid of the user to be added to the groupOfNames as a member.
#	p_groupCN: The cn(s) of the groupOfNames where the user must be added
#	userDN: (OPTIONAL) The DN used as parent of all the ou. If not set,
#		it uses the one read from the configuration file.
#	groupDN: (OPTIONAL) The DN used as parent of this new groupOfNames.
#		If not set, it uses the one read from the configuration file.
sub addMemberToGroup($$;$$) {
	my $self = shift;
	
	my($userUID,$p_groupCN,$userDN,$groupDN)=@_;
	
	return $self->addUserToGroup($userUID,undef,$p_groupCN,$userDN,$groupDN);
}

# Parameters:
#	userUID: The uid of the user to be added to the groupOfNames as an owner.
#	p_groupCN: The cn(s) of the groupOfNames where the user must be added
#	userDN: (OPTIONAL) The DN used as parent of all the ou. If not set,
#		it uses the one read from the configuration file.
#	groupDN: (OPTIONAL) The DN used as parent of this new groupOfNames.
#		If not set, it uses the one read from the configuration file.
sub addOwnerToGroup($$;$$) {
	my $self = shift;
	
	my($userUID,$p_groupCN,$userDN,$groupDN)=@_;
	
	return $self->addUserToGroup($userUID,1,$p_groupCN,$userDN,$groupDN);
}


# Parameters:
#	userUID: The uid of the user to be removed from the groupOfNames.
#	isOwner: Must this uid be removed as an owner instead of as a member?
#	p_groupCN: The cn(s) of the groupOfNames where the user must be removed from
#	userDN: (OPTIONAL) The DN used as parent of all the ou. If not set,
#		it uses the one read from the configuration file.
#	groupDN: (OPTIONAL) The DN used as parent of this new groupOfNames.
#		If not set, it uses the one read from the configuration file.
sub removeUserFromGroup($$$;$$) {
	my $self = shift;
	
	my($userUID,$isOwner,$p_groupCN,$userDN,$groupDN)=@_;
	
	$userDN = $self->{'userDN'}  unless(defined($userDN) && length($userDN)>0);
	$groupDN = $self->{'groupDN'}  unless(defined($groupDN) && length($groupDN)>0);
	
	$p_groupCN = [ $p_groupCN ]  unless(ref($p_groupCN) eq 'ARRAY');
	
	# First, the user must be found
	my($success, $payload) = $self->getUser($userUID,$userDN);
	#if($success && $payload->get_value('disabledAccount') eq 'TRUE') {
	#	$success = undef;
	#	$payload = [ 'Cannot modify a disabled user' ];
	#}
	
	if($success) {
		my $user = $payload;
		$payload = [];
		
		my @groupsToBeRemovedFromAsMember = ();
		my @groupsToBeRemovedFromAsOwner = ();
		
		REMOVE_USER_GROUPCN:
		foreach my $groupCN (@{$p_groupCN}) {
			# Second, each group of names must be found
			my($partialSuccess,$group) = $self->getGroup($groupCN,$groupDN);
			
			unless($partialSuccess) {
				$success = undef;
				push(@{$payload},@{$group});
				next;
			}
			
			if($isOwner) {
				my $p_owners = $group->get_value('owner', 'asref' => 1);
				foreach my $owner (@{$p_owners}) {
					if($owner eq $user->dn()) {
						push(@groupsToBeRemovedFromAsOwner,$group);
						last;
					}
				}
			} else {
				my $p_members = $group->get_value('member', 'asref' => 1);
				foreach my $member (@{$p_members}) {
					if($member eq $user->dn()) {
						push(@groupsToBeRemovedFromAsMember,$group);
						last;
					}
				}
			}
		}
		
		if($success && (scalar(@groupsToBeRemovedFromAsMember) > 0 || scalar(@groupsToBeRemovedFromAsOwner) > 0)) {
			if(scalar(@groupsToBeRemovedFromAsMember) > 0) {
				my @removeGroupDNs = map { $_->dn(); } @groupsToBeRemovedFromAsMember;
				
				# And, at last, add the group dn to the user's memberOf list
				$user->changetype('modify');
				$user->delete(USER_MEMBEROF_ATTRIBUTE() => \@removeGroupDNs);
				
				my $updMesg = $user->update($self->{'ldap'});
				
				if($updMesg->code() != Net::LDAP::LDAP_SUCCESS) {
					$success = undef;
					print STDERR $user->ldif()  unless(wantarray);
					
					push(@{$payload},"Unable to remove memberOf ".join(',',@removeGroupDNs)." from ".$user->dn()."\n".Dumper($updMesg));
				}
			}
			
			if($success) {
				foreach my $group (@groupsToBeRemovedFromAsMember) {
					# Now, remove the user dn from the group's member list
					$group->changetype('modify');
					$group->delete('member' => [ $user->dn() ]);
					
					my $updMesg = $group->update($self->{'ldap'});
					
					if($updMesg->code() != Net::LDAP::LDAP_SUCCESS) {
						$success = undef;
						print STDERR $group->ldif()  unless(wantarray);
						
						push(@{$payload},"Unable to remove member ".$user->dn()." from ".$group->dn()."\n".Dumper($updMesg));
						last;
					}
				}
				if($success) {
					foreach my $group (@groupsToBeRemovedFromAsOwner) {
						# Now, remove the user dn from the group's member list
						$group->changetype('modify');
						$group->delete('owner' => [ $user->dn() ]);
						
						my $updMesg = $group->update($self->{'ldap'});
						
						if($updMesg->code() != Net::LDAP::LDAP_SUCCESS) {
							$success = undef;
							print STDERR $group->ldif()  unless(wantarray);
							
							push(@{$payload},"Unable to remove owner ".$user->dn()." from ".$group->dn()."\n".Dumper($updMesg));
							last;
						}
					}
				}
			}
		}
	}
	
	if(wantarray) {
		return ($success,$payload);
	} else {
		unless($success) {
			foreach my $err (@{$payload}) {
				Carp::carp($err);
			}
		}
		
		return $success;
	} 
}

# Parameters:
#	userUID: The uid of the member to be removed from the groupOfNames.
#	p_groupCN: The cn(s) of the groupOfNames where the user must be removed from
#	userDN: (OPTIONAL) The DN used as parent of all the ou. If not set,
#		it uses the one read from the configuration file.
#	groupDN: (OPTIONAL) The DN used as parent of this new groupOfNames.
#		If not set, it uses the one read from the configuration file.
sub removeMemberFromGroup($$;$$) {
	my $self = shift;
	
	my($userUID,$p_groupCN,$userDN,$groupDN)=@_;
	
	return $self->removeUserFromGroup($userUID,undef,$p_groupCN,$userDN,$groupDN);
}

# Parameters:
#	userUID: The uid of the owner to be removed from the groupOfNames.
#	p_groupCN: The cn(s) of the groupOfNames where the user must be removed from
#	userDN: (OPTIONAL) The DN used as parent of all the ou. If not set,
#		it uses the one read from the configuration file.
#	groupDN: (OPTIONAL) The DN used as parent of this new groupOfNames.
#		If not set, it uses the one read from the configuration file.
sub removeOwnerFromGroup($$;$$) {
	my $self = shift;
	
	my($userUID,$p_groupCN,$userDN,$groupDN)=@_;
	
	return $self->removeUserFromGroup($userUID,1,$p_groupCN,$userDN,$groupDN);
}

# Parameters:
#	groupCN: The cn of the groupOfNames to be removed
#	groupDN: (OPTIONAL) The DN used as parent of this groupOfNames.
#		If not set, it uses the one read from the configuration file.
sub removeGroup($;$) {
	my $self = shift;
	
	my($groupCN,$groupDN)=@_;
	
	$groupDN = $self->{'groupDN'}  unless(defined($groupDN) && length($groupDN)>0);
	
	# Is the group found?
	my($success,$payload) = $self->getGroup($groupCN,$groupDN);
	
	if($success) {
		my $group = $payload;
		$payload = [];
		
		# Now, erasing the group (this operation CANNOT BE UNDONE!)
		my $delMesg = $group->delete()->update($self->{'ldap'});
		if($delMesg->code() != Net::LDAP::LDAP_SUCCESS) {
			$success = undef;
			push(@{$payload},"Error while removing $groupCN from $groupDN\n".Dumper($delMesg));
		}
	}
	
	if(wantarray) {
		return ($success,$payload);
	} else {
		unless($success) {
			foreach my $err (@{$payload}) {
				Carp::carp($err);
			}
		}
		
		return $success;
	} 
}


# Parameters:
#	oldGroupCN: The old cn of the groupOfNames to be renamed
#	newGroupCN: The new cn of the groupOfNames to be renamed
#	oldBaseGroupDN: (OPTIONAL) The DN used as parent of this groupOfNames.
#		If not set, it uses the one read from the configuration file.
#	newBaseGroupDN: (OPTIONAL) The DN used as parent of the renamed groupOfNames.
#		If not set, it uses the one read from the configuration file.
sub renameGroup($$;$$) {
	my $self = shift;
	
	my($oldGroupCN,$newGroupCN,$oldBaseGroupDN,$newBaseGroupDN)=@_;
	
	$oldBaseGroupDN = $self->{'groupDN'}  unless(defined($oldBaseGroupDN) && length($oldBaseGroupDN)>0);
	$newBaseGroupDN = $self->{'groupDN'}  unless(defined($newBaseGroupDN) && length($newBaseGroupDN)>0);
	my $parentDN = $self->{'parentDN'};
	
	# Is the group found?
	my($success,$payload) = $self->getGroup($oldGroupCN,$oldBaseGroupDN);
	
	my $escaped_newGroupCN;
	my $group;
	my $oldDn;
	my $newDn;
	if($success) {
		$group = $payload;
		$oldDn = $group->dn();
		
		$success = undef;
		$payload = [];
		
		$escaped_newGroupCN = Net::LDAP::Util::escape_filter_value($newGroupCN);
		my $e_newGroupDN = Net::LDAP::Util::ldap_explode_dn($newBaseGroupDN,@LDAP_UTIL_SERIALIZATION_PARAMS);
		unshift(@{$e_newGroupDN},{'cn' => $newGroupCN});
		$newDn = Net::LDAP::Util::canonical_dn($e_newGroupDN,@LDAP_UTIL_SERIALIZATION_PARAMS);
		
		# Is the new name in use?
		if($self->existsDN($newDn)) {
			push(@{$payload},"Error, $newGroupCN already exists under $newBaseGroupDN");
		} else {
			$success = 1;
		}
	}
	
	my @refEntries = ();
	# Fetching the entries referring to the group
	if($success) {
		my $escaped_oldDn = Net::LDAP::Util::escape_filter_value($oldDn);
		my $refSearchMesg = $self->{'ldap'}->search(
			'base'	=> $parentDN,
			'filter' => "(:distinguishedNameMatch:=$escaped_oldDn)",
			'scope' => 'sub',
		);
		
		$success = undef;
		
		if($refSearchMesg->code() == Net::LDAP::LDAP_SUCCESS) {
			@refEntries = $refSearchMesg->entries();
			$success = 1;
		} else {
			push(@{$payload},"Error while finding members of $oldDn\n".Dumper($refSearchMesg));
		}
	}
	
	if($success) {
		# Now, time to rename the group (and all the references to it)
		my $isMove = $oldBaseGroupDN ne $newBaseGroupDN;
		$group->changetype($isMove ? "moddn" : "modrdn");
		# The old entry will be erased later, when all the updates are in place
		$group->add(
			"deleteoldrdn" => 1,
			"newrdn" => "cn=$escaped_newGroupCN"
		);
		if($isMove) {
			$group->add(
				"newsuperior" => $newBaseGroupDN
			);
		}
		
		# Now, batch updates!
		my $updMesg = $group->update($self->{'ldap'});
		if($updMesg->code() == Net::LDAP::LDAP_SUCCESS) {
			foreach my $refEntry (@refEntries) {
				my @replacements = ();
				foreach my $attr ($refEntry->attributes()) {
					my $p_members = $refEntry->get_value($attr,"asref" => 1);
					my $didMatch = undef;
					my @newValues = ();
					foreach my $member (@{$p_members}) {
						my $val;
						if($member eq $oldDn) {
							$val = $newDn;
							$didMatch = 1;
						} else {
							$val = $member;
						}
						
						push(@newValues,$val);
						#print "ENTRY\n$oldDn\n$newDn\n$member\n$val\n";
					}
					
					if($didMatch) {
						push(@replacements, $attr => \@newValues);
					}
				}
				
				if(scalar(@replacements) > 0) {
					$refEntry->changetype("modify");
					$refEntry->replace(@replacements);
					my $refUpdMesg = $refEntry->update($self->{'ldap'});
					if($refUpdMesg->code() != Net::LDAP::LDAP_SUCCESS) {
						$success = undef;
						print STDERR $refEntry->ldif()  unless(wantarray);
						
						my $refDn = $refEntry->dn();
						push(@{$payload}, "Could not update entry $refDn\n".Dumper($refUpdMesg) );
						last;
					}
				}
				
			}
		} else {
			$success = undef;
			print STDERR $group->ldif()  unless(wantarray);
			
			push(@{$payload}, "Could not rename entry $oldDn\n".Dumper($updMesg) );
		}
	}
	
	if(wantarray) {
		return ($success,$payload);
	} else {
		unless($success) {
			foreach my $err (@{$payload}) {
				Carp::carp($err);
			}
		}
		
		return $success;
	} 
}


my @LDAP_RDDOCUMENT_DEFAULT_ATTRIBUTES = (
	'objectClass'	=>	 ['RDConnectDocument'],
);

# Parameters:
#	dn: The parent of the document.
#	ownerDN: The owner of the document.
#	p_documentMetadata: a reference to a hash with the required keys needed to create new document
#	data: The document itself as raw data
sub attachDocumentForEntry($$\%$) {
	my $self = shift;
	my($dn,$ownerDN,$p_documentMetadata,$data) = @_;
	
	# $p_entryArray,$m_getDN,$m_normalizePKJSON,$validator,$p_json2ldap,$hotchpotchAttribute,$p_ldap_default_attributes,$doReplace
	my $mimeType = 'application/octet-stream';
	
	# Trying to guess the type of file
	eval {
		$mimeType = File::MimeInfo::Magic::mimetype(IO::Scalar->new(\$data));
	};
	
	return $self->createLDAPFromJSON(
				$p_documentMetadata,
				sub {
					my $uMgmt = shift;
					
					my($jsonDocumentMetadata) = @_;
					my $cn = exists($jsonDocumentMetadata->{'cn'}) ? $jsonDocumentMetadata->{'cn'} : '';
					
					my $docdn = join(',','cn='.Net::LDAP::Util::escape_dn_value($cn),$dn);
					
					return $docdn;
				},
				\&_normalizeUserCNFromJSON,
				getCASRDDocumentValidator(),
				undef,
				\%JSON_LDAP_RDDOCUMENT_ATTRIBUTES,
				undef,
				[
					# Injecting the file itself, as these attributes are outside
					# of JSON data model due design decisions
					'content' => $data,
					'mimeType' => $mimeType,
					@LDAP_RDDOCUMENT_DEFAULT_ATTRIBUTES
				]
			);
}

# Parameters:
#	dn: the distinguished named of the parent entry
# It returns the list of documents attached to this distinguished name
sub listDocumentsFromEntry($) {
	my $self = shift;
	
	my($dn) = @_;
	
	# First, search the entries
	my $searchMesg = $self->{'ldap'}->search(
		'base' => $dn,
		# We know what we want
		'attrs'	=>	['cn','description','documentClass','createTimestamp','modifyTimestamp','creatorsName','modifiersName'],
		'filter' => "(objectClass=RDConnectDocument)",
		'sizelimit' => 10000,
		'scope' => 'children'
	);
	
	my $success = undef;
	my $payload = [];
	
	if($searchMesg->code() == Net::LDAP::LDAP_SUCCESS) {
		# Second, build the entry
		if($searchMesg->count>0) {
			$success = 1;
			$payload = [ $searchMesg->entries() ];
		#} else {
		#	push(@{$payload},"No matching user found for $username");
		}
	} else {
		push(@{$payload},"Error while finding entry $dn\n".Dumper($searchMesg));
	}
	
	if(wantarray) {
		return ($success,$payload);
	} else {
		unless($success) {
			foreach my $err (@{$payload}) {
				Carp::carp($err);
			}
		}
		
		return $success;
	} 
}

# Parameters:
#	dn: the distinguished named of the parent entry
sub listJSONDocumentsFromEntry($) {
	my $self = shift;
	
	my($dn) = @_;
	
	my($success,$payload) = $self->listDocumentsFromEntry($dn);
	
	if($success && defined($payload)) {
		$payload = $self->genJSONDocumentsFromLDAPDocuments($payload);
	}
	
	return ($success,$payload);
}

# Parameters:
#	dn: the distinguished named of the parent entry
#	documentName: the name of the document to look for
# It returns the document attached to this distinguished name
sub getDocumentFromEntry($$) {
	my $self = shift;
	
	my($dn,$documentName) = @_;
	
	# First, search the entries
	my $escaped_documentName = Net::LDAP::Util::escape_filter_value($documentName);
	my $searchMesg = $self->{'ldap'}->search(
		'base' => $dn,
		# We know what we want
		'attrs'	=>	['*','createTimestamp','modifyTimestamp','creatorsName','modifiersName'],
		'filter' => "(&(objectClass=RDConnectDocument)(cn=".$escaped_documentName."))",
		'sizelimit' => 1,
		'scope' => 'children'
	);
	
	my $success = undef;
	my $payload = undef;
	
	if($searchMesg->code() == Net::LDAP::LDAP_SUCCESS) {
		# Second, build the entry
		$success = 1;
		if($searchMesg->count>0) {
			$payload = $searchMesg->entry(0);
		#} else {
		#	push(@{$payload},"No matching user found for $username");
		}
	#} elsif($searchMesg->code() == Net::LDAP::LDAP_SUCCESS) {
	#	$success = 1;
	} else {
		$payload = ["Error while finding entry $dn\n".Dumper($searchMesg)];
	}
	
	if(wantarray) {
		return ($success,$payload);
	} else {
		unless($success) {
			foreach my $err (@{$payload}) {
				Carp::carp($err);
			}
		}
		
		return $success;
	} 
}

# Parameters:
#	dn: the distinguished named of the parent entry
#	documentName: the name of the document to look for
# It returns the document attached to this distinguished name
sub getJSONDocumentMetadataFromEntry($$) {
	my $self = shift;
	
	my($dn,$documentName) = @_;
	
	my($success,$payload) = $self->getDocumentFromEntry($dn,$documentName);
	my $documentMetadataEntry = undef;
	
	if($success && defined($payload)) {
		$documentMetadataEntry = $payload;
		$payload = $self->genJSONDocumentsFromLDAPDocuments([ $documentMetadataEntry ])->[0];
	}
	
	return ($success,$payload,$documentMetadataEntry);
}

# Parameters:
#	dn: the distinguished named of the parent entry
#	documentName: the name of the document to look for
#	p_metadataHash: a reference to a hash with the modified organizational unit information
#	p_removedKeys: a reference to an array with the removed keys
# It returns the LDAP entry on success
sub modifyJSONDocumentMetadataFromEntry($$\%;\@) {
	my $self = shift;
	
	my($dn,$documentName,$p_metadataHash,$p_removedKeys) = @_;
	
	my($success,$payload,$documentEntry) = $self->getJSONDocumentMetadataFromEntry($dn,$documentName);
	
	if($success) {
		# $jsonEntry,$entry,$p_entryHash,$p_json2ldap,$validator,$hotchpotchAttribute,$p_ldap_default_attributes
		my $jsonDocumentEntry = $payload;
		($success,$payload,$documentEntry) = $self->modifyJSONEntry(
							$jsonDocumentEntry,
							$documentEntry,
							$p_metadataHash,
							\%JSON_LDAP_RDDOCUMENT_ATTRIBUTES,
							getCASRDDocumentValidator(),
							undef,
							\@LDAP_RDDOCUMENT_DEFAULT_ATTRIBUTES
						);
	} else {
		push(@{$payload},'Problems fetching the document metadata before modifying it');
	}
	
	if(wantarray) {
		return ($success,$payload,$documentEntry);
	} else {
		unless($success) {
			foreach my $err (@{$payload}) {
				Carp::carp($err);
			}
		}
		
		return $success;
	} 
}

# Parameters:
#	dn: the distinguished named of the parent entry
#	documentName: the name of the document to look for
#	data: The raw document
sub modifyDocumentFromEntry($$$) {
	my $self = shift;
	
	my($dn,$documentName,$data) = @_;
	
	my($success,$payload) = $self->getDocumentFromEntry($dn,$documentName);
	my $documentMetadataEntry = undef;
	
	if($success && defined($payload)) {
		my $mimeType = 'application/octet-stream';
		
		# Trying to guess the type of file
		eval {
			$mimeType = File::MimeInfo::Magic::mimetype(IO::Scalar->new(\$data));
		};
		
		# Silent "magic" errors
		#if($@) {
		#	print STDERR $@,"\n";
		#}
		
		my $document = $payload;
		my $dn = $document->dn();
		$document->changetype('modify');
		$document->replace(
			'content'	=>	$data,
			'mimeType'	=>	$mimeType,
		);

		my $updMesg = $document->update($self->{'ldap'});
		if($updMesg->code() != Net::LDAP::LDAP_SUCCESS) {
			$success = undef;
			print STDERR $document->ldif()  unless(wantarray);
			
			$payload = [ "Unable to set content for document $dn\n".Dumper($updMesg) ];
		}
	}
	
	if(wantarray) {
		return ($success,$payload);
	} else {
		unless($success) {
			foreach my $err (@{$payload}) {
				Carp::carp($err);
			}
		}
		
		return $success;
	} 
}

# Parameters:
#	dn: the distinguished named of the parent entry
#	documentName: the name of the document to look for
sub removeDocumentFromEntry($$) {
	my $self = shift;
	
	my($dn,$documentName,$data) = @_;
	
	my $docdn = join(',','cn='.Net::LDAP::Util::escape_dn_value($documentName),$dn);
	my $deleteMesg = $self->{'ldap'}->delete($docdn);
	
	my $success = $deleteMesg->code() == Net::LDAP::LDAP_SUCCESS;
	my $payload;
	
	if($success) {
		$payload = [ ];
	} else {
		$payload = [ "Error while removing document entry $docdn\n".Dumper($deleteMesg) ];
	}
	
	return ($success,$payload);
}


# Parameters:
#	username: the RD-Connect username or user e-mail
#	p_documentMetadata: a reference to a hash with the required keys needed to create new document
#	data: The document itself as raw data
#	userDN: (OPTIONAL) The DN used as ancestor of this username. If not set,
#		it uses the one read from the configuration file.
sub attachDocumentForUser($\%$;$) {
	my $self = shift;
	
	my($username,$p_documentMetadata,$data,$userDN) = @_;
	
	my($success,$payload) = $self->getUser($username,$userDN);
	
	if($success) {
		if(defined($payload)) {
			# The payload is the found user
			my $dn = $payload->dn();
			($success,$payload) = $self->attachDocumentForEntry($dn,$dn,$p_documentMetadata,$data);
		} else {
			$success = undef;
			$payload = ['User '.$username.' not found'];
		}
	}
	
	return ($success,$payload);
}

# Parameters:
#	username: the RD-Connect username or user e-mail
#	userDN: (OPTIONAL) The DN used as ancestor of this username. If not set,
#		it uses the one read from the configuration file.
sub listJSONDocumentsFromUser($;$) {
	my $self = shift;
	
	my($username,$userDN) = @_;
	
	my($success,$payload) = $self->getUser($username,$userDN);
	
	if($success) {
		if(defined($payload)) {
			# The payload is the found user
			my $dn = $payload->dn();
			($success,$payload) = $self->listJSONDocumentsFromEntry($dn);
		} else {
			$success = undef;
			$payload = ['User '.$username.' not found'];
		}
	}
	
	return ($success,$payload);
}

# Parameters:
#	username: the RD-Connect username or user e-mail
#	documentName: the name of the document to look for
#	userDN: (OPTIONAL) The DN used as ancestor of this username. If not set,
#		it uses the one read from the configuration file.
sub getDocumentFromUser($$;$) {
	my $self = shift;
	
	my($username,$documentName,$userDN) = @_;
	
	my($success,$payload) = $self->getUser($username,$userDN);
	
	if($success) {
		if(defined($payload)) {
			# The payload is the found user
			my $dn = $payload->dn();
			($success,$payload) = $self->getDocumentFromEntry($dn,$documentName);
		} else {
			$success = undef;
			$payload = ['User '.$username.' not found'];
		}
	}
	
	return ($success,$payload);
}

# Parameters:
#	username: the RD-Connect username or user e-mail
#	documentName: the name of the document to look for
#	userDN: (OPTIONAL) The DN used as ancestor of this username. If not set,
#		it uses the one read from the configuration file.
sub getJSONDocumentMetadataFromUser($$;$) {
	my $self = shift;
	
	my($username,$documentName,$userDN) = @_;
	
	my($success,$payload) = $self->getUser($username,$userDN);
	my $documentMetadataEntry = undef;
	
	if($success) {
		if(defined($payload)) {
			# The payload is the found user
			my $dn = $payload->dn();
			($success,$payload,$documentMetadataEntry) = $self->getJSONDocumentMetadataFromEntry($dn,$documentName);
		} else {
			$success = undef;
			$payload = ['User '.$username.' not found'];
		}
	}
	
	return ($success,$payload,$documentMetadataEntry);
}

# Parameters:
#	username: the RD-Connect username or user e-mail
#	documentName: the name of the document to look for
#	p_metadataHash: a reference to a hash with the modified organizational unit information
#	p_removedKeys: a reference to an array with the removed keys
#	userDN: (OPTIONAL) The DN used as ancestor of this username. If not set,
#		it uses the one read from the configuration file.
# It returns the LDAP entry on success
sub modifyJSONDocumentMetadataFromUser($$\%;\@$) {
	my $self = shift;
	
	my($username,$documentName,$p_metadataHash,$p_removedKeys,$userDN) = @_;
	
	my($success,$payload) = $self->getUser($username,$userDN);
	my $documentMetadataEntry = undef;
	
	if($success) {
		if(defined($payload)) {
			# The payload is the found user
			my $dn = $payload->dn();
			($success,$payload,$documentMetadataEntry) = $self->modifyJSONDocumentMetadataFromEntry($dn,$documentName,$p_metadataHash,$p_removedKeys);
		} else {
			$success = undef;
			$payload = ['User '.$username.' not found'];
		}
	}
	
	return ($success,$payload,$documentMetadataEntry);
}

# Parameters:
#	username: the RD-Connect username or user e-mail
#	documentName: the name of the document to look for
#	data: The raw file content
#	userDN: (OPTIONAL) The DN used as ancestor of this username. If not set,
#		it uses the one read from the configuration file.
# It returns the LDAP entry on success
sub modifyDocumentFromUser($$$;$) {
	my $self = shift;
	
	my($username,$documentName,$data,$userDN) = @_;
	
	my($success,$payload) = $self->getUser($username,$userDN);
	
	if($success) {
		if(defined($payload)) {
			# The payload is the found user
			my $dn = $payload->dn();
			($success,$payload) = $self->modifyDocumentFromEntry($dn,$documentName,$data);
		} else {
			$success = undef;
			$payload = ['User '.$username.' not found'];
		}
	}
	
	return ($success,$payload);
}

# Parameters:
#	username: the RD-Connect username or user e-mail
#	documentName: the name of the document to look for
#	userDN: (OPTIONAL) The DN used as ancestor of this username. If not set,
#		it uses the one read from the configuration file.
# It returns the LDAP entry on success
sub removeDocumentFromUser($$;$) {
	my $self = shift;
	
	my($username,$documentName,$userDN) = @_;
	
	my($success,$payload) = $self->getUser($username,$userDN);
	
	if($success) {
		if(defined($payload)) {
			# The payload is the found user
			my $dn = $payload->dn();
			($success,$payload) = $self->removeDocumentFromEntry($dn,$documentName);
		} else {
			$success = undef;
			$payload = ['User '.$username.' not found'];
		}
	}
	
	return ($success,$payload);
}


# Parameters:
#	groupCN: the RD-Connect group
#	p_documentMetadata: a reference to a hash with the required keys needed to create new document
#	data: The document itself as raw data
#	groupDN: (OPTIONAL) The DN used as ancestor of this group.
#		 If not set, it uses the one read from the configuration file.
sub attachDocumentForGroup($\%$;$) {
	my $self = shift;
	
	my($groupCN,$p_documentMetadata,$data,$groupDN) = @_;
	
	my($success,$payload) = $self->getGroup($groupCN,$groupDN);
	
	if($success) {
		if(defined($payload)) {
			# The payload is the found group
			my $dn = $payload->dn();
			($success,$payload) = $self->attachDocumentForEntry($dn,$dn,$p_documentMetadata,$data);
		} else {
			$success = undef;
			$payload = ['Group '.$groupCN.' not found'];
		}
	}
	
	return ($success,$payload);
}
	
# Parameters:
#	groupCN: the RD-Connect group
#	groupDN: (OPTIONAL) The DN used as ancestor of this group.
#		 If not set, it uses the one read from the configuration file.
sub listJSONDocumentsFromGroup($;$) {
	my $self = shift;
	
	my($groupCN,$groupDN) = @_;
	
	my($success,$payload) = $self->getGroup($groupCN,$groupDN);
	
	if($success) {
		if(defined($payload)) {
			# The payload is the found group
			my $dn = $payload->dn();
			($success,$payload) = $self->listJSONDocumentsFromEntry($dn);
		} else {
			$success = undef;
			$payload = ['Group '.$groupCN.' not found'];
		}
	}
	
	return ($success,$payload);
}

# Parameters:
#	groupCN: the RD-Connect group
#	documentName: the name of the document to look for
#	groupDN: (OPTIONAL) The DN used as ancestor of this group.
#		 If not set, it uses the one read from the configuration file.
sub getDocumentFromGroup($$;$) {
	my $self = shift;
	
	my($groupCN,$documentName,$groupDN) = @_;
	
	my($success,$payload) = $self->getGroup($groupCN,$groupDN);
	
	if($success) {
		if(defined($payload)) {
			# The payload is the found group
			my $dn = $payload->dn();
			($success,$payload) = $self->getDocumentFromEntry($dn,$documentName);
		} else {
			$success = undef;
			$payload = ['Group '.$groupCN.' not found'];
		}
	}
	
	return ($success,$payload);
}

# Parameters:
#	groupCN: the RD-Connect group
#	documentName: the name of the document to look for
#	groupDN: (OPTIONAL) The DN used as ancestor of this group.
#		 If not set, it uses the one read from the configuration file.
sub getJSONDocumentMetadataFromGroup($$;$) {
	my $self = shift;
	
	my($groupCN,$documentName,$groupDN) = @_;
	
	my($success,$payload) = $self->getGroup($groupCN,$groupDN);
	my $documentMetadataEntry = undef;
	
	if($success) {
		if(defined($payload)) {
			# The payload is the found group
			my $dn = $payload->dn();
			($success,$payload,$documentMetadataEntry) = $self->getJSONDocumentMetadataFromEntry($dn,$documentName);
		} else {
			$success = undef;
			$payload = ['Group '.$groupCN.' not found'];
		}
	}
	
	return ($success,$payload,$documentMetadataEntry);
}

# Parameters:
#	groupCN: the RD-Connect group
#	documentName: the name of the document to look for
#	p_metadataHash: a reference to a hash with the modified metadata information
#	p_removedKeys: (OPTIONAL) a reference to an array with the removed keys
#	groupDN: (OPTIONAL) The DN used as ancestor of this group.
#		 If not set, it uses the one read from the configuration file.
# It returns the LDAP entry on success
sub modifyJSONDocumentMetadataFromGroup($$\%;\@$) {
	my $self = shift;
	
	my($groupCN,$documentName,$p_metadataHash,$p_removedKeys,$groupDN) = @_;
	
	my($success,$payload) = $self->getGroup($groupCN,$groupDN);
	my $documentMetadataEntry = undef;
	
	if($success) {
		if(defined($payload)) {
			# The payload is the found group
			my $dn = $payload->dn();
			($success,$payload,$documentMetadataEntry) = $self->modifyJSONDocumentMetadataFromEntry($dn,$documentName,$p_metadataHash,$p_removedKeys);
		} else {
			$success = undef;
			$payload = ['Group '.$groupCN.' not found'];
		}
	}
	
	return ($success,$payload,$documentMetadataEntry);
}

# Parameters:
#	groupCN: the RD-Connect group
#	documentName: the name of the document to look for
#	data: The raw document data
#	groupDN: (OPTIONAL) The DN used as ancestor of this group.
#		 If not set, it uses the one read from the configuration file.
# It returns the LDAP entry on success
sub modifyDocumenFromGroup($$$;$) {
	my $self = shift;
	
	my($groupCN,$documentName,$data,$groupDN) = @_;
	
	my($success,$payload) = $self->getGroup($groupCN,$groupDN);
	
	if($success) {
		if(defined($payload)) {
			# The payload is the found group
			my $dn = $payload->dn();
			($success,$payload) = $self->modifyDocumentFromEntry($dn,$documentName,$data);
		} else {
			$success = undef;
			$payload = ['Group '.$groupCN.' not found'];
		}
	}
	
	return ($success,$payload);
}

# Parameters:
#	groupCN: the RD-Connect group
#	documentName: the name of the document to look for
#	groupDN: (OPTIONAL) The DN used as ancestor of this group.
#		 If not set, it uses the one read from the configuration file.
# It returns the LDAP entry on success
sub removeDocumenFromGroup($$;$) {
	my $self = shift;
	
	my($groupCN,$documentName,$groupDN) = @_;
	
	my($success,$payload) = $self->getGroup($groupCN,$groupDN);
	
	if($success) {
		if(defined($payload)) {
			# The payload is the found group
			my $dn = $payload->dn();
			($success,$payload) = $self->removeDocumentFromEntry($dn,$documentName);
		} else {
			$success = undef;
			$payload = ['Group '.$groupCN.' not found'];
		}
	}
	
	return ($success,$payload);
}


############
# Domains #
##########
# All the domains hang from the organization
# and all of them are organizationRole
use constant DomainEntryRole	=>	'organizationalRole';
my @LDAP_DOMAIN_DEFAULT_ATTRIBUTES = (
	'objectClass'	=>	 [ DomainEntryRole ],
);

use constant NewUserDomain	=>	'newUserTemplates';

# Parameters:
#	domainCN: The short, domain name, which will hang on parentDN
sub createDomain($) {
	my $self = shift;
	
	my($domainCN) = @_;
	
	my $entry = Net::LDAP::Entry->new();
	my $dn = join(',','cn='.Net::LDAP::Util::escape_dn_value($domainCN),$self->{'parentDN'});
	$entry->dn($dn);
	$entry->add(
		'cn'	=>	$domainCN,
		@LDAP_DOMAIN_DEFAULT_ATTRIBUTES
	);
	
	my $updMesg = $entry->update($self->{'ldap'});
	
	if($updMesg->code() != Net::LDAP::LDAP_SUCCESS) {
		print STDERR $entry->ldif();
		
		Carp::carp("Unable to create domain $dn (does the domain already exist?)\n".Dumper($updMesg));
	}
	return $updMesg->code() == Net::LDAP::LDAP_SUCCESS;
}

# Parameters:
#	domainCN: the RD-Connect domain
#	createWhenMissing: if it is true, the domain is created when it is not found
# It returns the LDAP entry of the domain on success
sub getDomain($;$) {
	my $self = shift;
	
	my($domainCN,$createWhenMissing) = @_;
	
	# First, each owner must be found
	my $escaped_domainCN = Net::LDAP::Util::escape_filter_value($domainCN);
	my $searchMesg = $self->{'ldap'}->search(
		'base' => $self->{'parentDN'},
		'filter' => "(&(objectClass=".DomainEntryRole.")(cn=$escaped_domainCN))",
		'sizelimit' => 1,
		'scope' => 'children'
	);
	
	my $success = undef;
	my $payload = [];
	
	if($searchMesg->code() == Net::LDAP::LDAP_SUCCESS) {
		if($searchMesg->count>0) {
			$success = 1;
			# The user entry
			$payload = $searchMesg->entry(0);
		} else {
			if($createWhenMissing && $self->createDomain($domainCN)) {
				return $self->getDomain($domainCN);
			} else {
				push(@{$payload},"No matching domain found for $domainCN");
			}
		}
	} else {
		push(@{$payload},"Error while finding domain $domainCN\n".Dumper($searchMesg));
	}
	
	if(wantarray) {
		return ($success,$payload);
	} else {
		unless($success) {
			foreach my $err (@{$payload}) {
				Carp::carp($err);
			}
		}
		
		return $success;
	} 
}

# Parameters:
#	domainCN: the RD-Connect domain
sub listJSONDocumentsFromDomain($) {
	my $self = shift;
	
	my($domainCN) = @_;
	
	my($success,$payload) = $self->getDomain($domainCN);
	
	if($success) {
		if(defined($payload)) {
			# The payload is the found group
			my $dn = $payload->dn();
			($success,$payload) = $self->listJSONDocumentsFromEntry($dn);
		} else {
			$success = undef;
			$payload = ['Domain '.$domainCN.' not found'];
		}
	}
	
	return ($success,$payload);
}

# Parameters:
#	domainCN: the RD-Connect domain
#	documentName: the name of the document to look for
sub getDocumentFromDomain($$) {
	my $self = shift;
	
	my($domainCN,$documentName) = @_;
	
	my($success,$payload) = $self->getDomain($domainCN);
	
	if($success) {
		if(defined($payload)) {
			# The payload is the found group
			my $dn = $payload->dn();
			($success,$payload) = $self->getDocumentFromEntry($dn,$documentName);
		} else {
			$success = undef;
			$payload = ['Domain '.$domainCN.' not found'];
		}
	}
	
	return ($success,$payload);
}

# Parameters:
#	domainCN: the RD-Connect domain
#	documentName: the name of the document to look for
sub getJSONDocumentMetadataFromDomain($$) {
	my $self = shift;
	
	my($domainCN,$documentName) = @_;
	
	my($success,$payload) = $self->getDomain($domainCN);
	my $documentMetadataEntry = undef;
	
	if($success) {
		if(defined($payload)) {
			# The payload is the found group
			my $dn = $payload->dn();
			($success,$payload,$documentMetadataEntry) = $self->getJSONDocumentMetadataFromEntry($dn,$documentName);
		} else {
			$success = undef;
			$payload = ['Domain '.$domainCN.' not found'];
		}
	}
	
	return ($success,$payload,$documentMetadataEntry);
}

# Parameters:
#	domainCN: the RD-Connect domain
#	documentName: the name of the document to look for
#	p_metadataHash: a reference to a hash with the modified metadata information
#	p_removedKeys: (OPTIONAL) a reference to an array with the removed keys
# It returns the LDAP entry on success
sub modifyJSONDocumentMetadataFromDomain($$\%;\@) {
	my $self = shift;
	
	my($domainCN,$documentName,$p_metadataHash,$p_removedKeys) = @_;
	
	my($success,$payload) = $self->getDomain($domainCN);
	my $documentMetadataEntry = undef;
	
	if($success) {
		if(defined($payload)) {
			# The payload is the found group
			my $dn = $payload->dn();
			($success,$payload,$documentMetadataEntry) = $self->modifyJSONDocumentMetadataFromEntry($dn,$documentName,$p_metadataHash,$p_removedKeys);
		} else {
			$success = undef;
			$payload = ['Domain '.$domainCN.' not found'];
		}
	}
	
	return ($success,$payload,$documentMetadataEntry);
}

# Parameters:
#	domainCN: the RD-Connect domain
#	documentName: the name of the document to look for
#	data: The raw document data
# It returns the LDAP entry on success
sub modifyDocumentFromDomain($$$) {
	my $self = shift;
	
	my($domainCN,$documentName,$data) = @_;
	
	my($success,$payload) = $self->getDomain($domainCN);
	
	if($success) {
		if(defined($payload)) {
			# The payload is the found group
			my $dn = $payload->dn();
			($success,$payload) = $self->modifyDocumentFromEntry($dn,$documentName,$data);
		} else {
			$success = undef;
			$payload = ['Domain '.$domainCN.' not found'];
		}
	}
	
	return ($success,$payload);
}

# Parameters:
#	domainCN: the RD-Connect domain
#	p_documentMetadata: a reference to a hash with the required keys needed to create new document
#	data: The document itself as raw data
sub attachDocumentForDomain($\%$) {
	my $self = shift;
	
	my($domainCN,$p_documentMetadata,$data) = @_;
	
	my($success,$payload) = $self->getDomain($domainCN,1);
	
	if($success) {
		if(defined($payload)) {
			# The payload is the found group
			my $dn = $payload->dn();
			($success,$payload) = $self->attachDocumentForEntry($dn,$dn,$p_documentMetadata,$data);
		} else {
			$success = undef;
			$payload = ['Domain '.$domainCN.' not found'];
		}
	}
	
	return ($success,$payload);
}

# Parameters:
#	domainCN: the RD-Connect domain
#	documentName: the name of the document to look for
# It returns the LDAP entry on success
sub removeDocumentFromDomain($$) {
	my $self = shift;
	
	my($domainCN,$documentName) = @_;
	
	my($success,$payload) = $self->getDomain($domainCN);
	
	if($success) {
		if(defined($payload)) {
			# The payload is the found group
			my $dn = $payload->dn();
			($success,$payload) = $self->removeDocumentFromEntry($dn,$documentName);
		} else {
			$success = undef;
			$payload = ['Domain '.$domainCN.' not found'];
		}
	}
	
	return ($success,$payload);
}


# Parameters:
#	keyName: the key name of the alias
#	keyValue: they key value of the alias
#	parentDN: the parent DN where the alias is going to live
#	aliasedObjectName: the DN of the aliased object
sub createAlias($$$$;$) {
	my $self = shift;
	
	my($keyName,$keyValue,$parentDN,$aliasedObjectName,$doReplace)=@_;
	
	my $entry = Net::LDAP::Entry->new();
	$entry->changetype('modify')  if($doReplace);
	my $dn = join(',',Net::LDAP::Util::escape_dn_value($keyName).'='.Net::LDAP::Util::escape_dn_value($keyValue),$parentDN);
	$entry->dn($dn);
	$entry->add(
		'objectClass'	=>	[ 'alias', 'extensibleObject' ],
		$keyName	=>	$keyValue,
		'aliasedObjectName'	=>	$aliasedObjectName
	);
	
	my $updMesg = $entry->update($self->{'ldap'});
	
	if($updMesg->code() != Net::LDAP::LDAP_SUCCESS) {
		print STDERR $entry->ldif();
		
		Carp::carp("Unable to create alias $dn pointing to $aliasedObjectName (does it exist?)\n".Dumper($updMesg));
	}
	return $updMesg->code() == Net::LDAP::LDAP_SUCCESS;
}

1;

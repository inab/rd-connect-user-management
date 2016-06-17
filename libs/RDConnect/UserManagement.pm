#!/usr/bin/perl -w

use strict;
package RDConnect::UserManagement;

use Carp;
use Config::IniFiles;
use Digest;
use MIME::Base64;
use Net::LDAP;
use Net::LDAP::Entry;
use boolean qw();

use constant LDAP_SECTION	=>	'ldap';

my %AcceptedLDAPSchemes = (
	'ldap'	=>	undef,
	'ldaps'	=>	undef,
	'ldapi'	=>	undef,
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
	my $userDN = $cfg->val(LDAP_SECTION,'userDN');
	Carp::croak("userDN parameter was not defined in $configFile")  unless(defined($userDN));
	my $groupDN = $cfg->val(LDAP_SECTION,'groupDN');
	Carp::croak("groupDN parameter was not defined in $configFile")  unless(defined($groupDN));
	
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
	$self->{'ldap'} = $ldap;
	$self->{'userDN'} = $userDN;
	$self->{'groupDN'} = $groupDN;
	$self->{'defaultGroupOU'} = $defaultGroupOU;
	
	return bless($self,$class);
}

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

	my $entry = Net::LDAP::Entry->new();
	$entry->changetype('modify')  if($doReplace);
	my $dn = join(',','cn='.$cn,'ou='.$groupOU,$self->{'userDN'});
	$entry->dn($dn);
	$entry->add(
		'givenName'	=>	$givenName,
		'sn'	=>	$sn,
		'userPassword'	=>	$hashedPasswd64,
		'objectClass'	=>	 ['basicRDproperties','inetOrgPerson','top'],
		'uid'	=>	$username,
		'disabledAccount'	=>	($active ? 'FALSE':'TRUE'),
		'cn'	=>	$cn,
		'mail'	=>	$email
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

{

	use JSON::Validator;
	use File::Basename ();
	use File::Spec;

	use constant USER_VALIDATION_SCHEMA_FILE	=>	'userValidation.json';
	my $userValidator = undef;

	sub getCASUserValidator() {
		unless(defined($userValidator)) {
			my $userSchemaPath = File::Spec->catfile(File::Basename::dirname(__FILE__),USER_VALIDATION_SCHEMA_FILE);
			if(-r $userSchemaPath) {
				$userValidator = JSON::Validator->new();
				$userValidator->schema($userSchemaPath);
			}
		}
		
		return $userValidator;
	}

}

# Correspondence between JSON attribute names and LDAP attribute names
# and whether these attributes should be masked on return
my %JSON_LDAP_USER_ATTRIBUTES = (
	'givenName'	=>	['givenName',boolean::true, undef, undef],
	'surname'	=>	['sn',boolean::true, undef, undef],
	'hashedPasswd64'	=>	['userPassword',boolean::false, undef, undef],
	'username'	=>	['uid',boolean::true, undef, undef],
	'enabled'	=>	['disabledAccount',boolean::true, sub { return ($_[0] ? 'FALSE':'TRUE'); }, sub { return (defined($_[0]) && $_[0] eq 'TRUE'); }],
	'cn'	=>	['cn',boolean::true, undef, undef],
	'email'	=>	['mail',boolean::true, undef, undef],
	
	'employeeType'	=>	['employeeType',boolean::true, undef, undef],
	'title'	=>	['title',boolean::true, undef, undef],
	'jpegPhoto'	=>	['jpegPhoto',boolean::true, undef, undef],
	'telephoneNumber'	=>	['telephoneNumber',boolean::true, undef, undef],
	'facsimileTelephoneNumber'	=>	['facsimileTelephoneNumber',boolean::false, undef, undef],
	'registeredAddress'	=>	['registeredAddress',boolean::false, undef, undef],
	'postalAddress'	=>	['postalAddress',boolean::false, undef, undef],
);

# Inverse correspondence: LDAP attributes to JSON ones
my %LDAP_JSON_USER_ATTRIBUTES = ();
@LDAP_JSON_USER_ATTRIBUTES{map { return $JSON_LDAP_USER_ATTRIBUTES{$_}[0]; } keys(%JSON_LDAP_USER_ATTRIBUTES)} = map { return [ $_,$JSON_LDAP_USER_ATTRIBUTES{$_}[1..$#{$JSON_LDAP_USER_ATTRIBUTES{$_}}] ]; } keys(%JSON_LDAP_USER_ATTRIBUTES);

# Which attributes do we have to mask?
my @JSON_MASK_USER_ATTRIBUTES = ();
foreach my $p_jsonDesc (values(%LDAP_JSON_USER_ATTRIBUTES)) {
	unless($p_jsonDesc->[1]) {
		push(@JSON_MASK_USER_ATTRIBUTES, $p_jsonDesc->[0]);
	}
}

use constant USER_HOTCHPOTCH_ATTRIBUTE	=> 	'description';

my @LDAP_USER_DEFAULT_ATTRIBUTES = (
	'objectClass'	=>	 ['basicRDproperties','inetOrgPerson','top'],
);

use constant LDAP_USER_HOTCHPOTCH	=>	'description';


# Parameters:
#	p_userArray: a reference to a hash or an array of hashes with the required keys needed to create new users
#	doReplace: if true, the entry is an update
sub createExtUser(\[%@];$) {
	my $self = shift;
	
	my($p_userArray,$groupOU,$doReplace) = @_;
	#my($username,$hashedPasswd64,$groupOU,$cn,$givenName,$sn,$email,$active,$doReplace) = @_;
	
	if(ref($p_userArray) ne 'ARRAY') {
		if(ref($p_userArray) eq 'HASH') {
			$p_userArray = [ $p_userArray ];
		} else {
			my $p_err = ['Input user must be either an array or a hash ref!'];
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
	my $userVal = getCASUserValidator();
	
	my $failed = undef;
	my $p_err = [];
	foreach my $p_userHash (@{$p_userArray}) {
		# Breaking when something cannot be validated
		unless(ref($p_userHash) eq 'HASH') {
			$failed = 1;
			push(@{$p_err},'All the input users in an array must be hash refs!');
			next;
		}
		
		# GroupOU normalization
		my $groupOU = exists($p_userHash->{'organizationalUnit'}) ? $p_userHash->{'organizationalUnit'} : undef;
		if(defined($groupOU) && length($groupOU) > 0) {
			$groupOU =~ s/^\s+//;
			$groupOU =~ s/\s+$//;
		}
		
		$groupOU = $self->{'defaultGroupOU'}  unless(defined($groupOU) && length($groupOU) > 0);
		$p_userHash->{'organizationalUnit'} = $groupOU;
		
		# Now, the validation of each input
		my @valErrors = $userVal->validate($p_userHash);
		if(scalar(@valErrors) > 0) {
			$failed = 1;
			
			my $cn = exists($p_userHash->{'cn'}) ? $p_userHash->{'cn'} : '';
			
			my $dn = join(',','cn='.$cn,'ou='.$p_userHash->{'organizationalUnit'},$self->{'userDN'});
			
			push(@{$p_err},"Validation errors for user $dn\n".join("\n",map { return "\tPath: ".$_->{'path'}.' . Message: '.$_->{'message'}} @valErrors));
		} else {
			# cn normalization
			unless(exists($p_userHash->{'cn'})) {
				$p_userHash->{'cn'} = $p_userHash->{'givenName'} .' '.$p_userHash->{'surname'};
			}
			
			push(@{$p_err},'');
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
	foreach my $p_userHash (@{$p_userArray}) {
		# Let's work!
		my $entry = Net::LDAP::Entry->new();
		$entry->changetype('modify')  if($doReplace);
		
		my $dn = join(',','cn='.$p_userHash->{'cn'},'ou='.$p_userHash->{'organizationalUnit'},$self->{'userDN'});
		$entry->dn($dn);
		
		my @userAttributes = ();
		
		# First, the common LDAP attributes
		push(@userAttributes,@LDAP_USER_DEFAULT_ATTRIBUTES);
		
		# Next, the attributes which go straight to LDAP
		foreach my $jsonKey (keys(%{$p_userHash})) {
			if(exists($JSON_LDAP_USER_ATTRIBUTES{$jsonKey})) {
				my $ldapVal = defined($JSON_LDAP_USER_ATTRIBUTES{$jsonKey}[2]) ? $JSON_LDAP_USER_ATTRIBUTES{$jsonKey}[2]->($p_userHash->{$jsonKey}) : $p_userHash->{$jsonKey};
				push(@userAttributes,$JSON_LDAP_USER_ATTRIBUTES{$jsonKey}[0] => $ldapVal);
			}
		}
		
		# Last, mask attributes and store the whole JSON in the hotchpotch
		foreach my $jsonKey (@JSON_MASK_USER_ATTRIBUTES) {
			delete($p_userHash->{$jsonKey})  if(exists($p_userHash->{$jsonKey}));
		}
		push(@userAttributes, USER_HOTCHPOTCH_ATTRIBUTE() => $j->encode($p_userHash));
		
		$entry->add(@userAttributes);
		
		my $updMesg = $entry->update($self->{'ldap'});
		if($updMesg->code() != Net::LDAP::LDAP_SUCCESS) {
			$p_err = [ "Unable to create user $dn (does the user already exist?)\n".Dumper($updMesg) ];
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
	
	return wantarray ? (1,$p_userArray) : 1;
}

# Parameters:
#	username: the RD-Connect username or user e-mail
#	userDN: (OPTIONAL) The DN used as parent of this new ou. If not set,
#		it uses the one read from the configuration file.
# It returns the LDAP entry of the user on success
sub getUser($;$) {
	my $self = shift;
	
	my($username,$userDN) = @_;
	
	$userDN = $self->{'userDN'}  unless(defined($userDN) && length($userDN)>0);
	
	# First, each owner must be found
	my $searchMesg = $self->{'ldap'}->search(
		'base' => $userDN,
		'filter' => "(&(objectClass=basicRDproperties)(|(uid=$username)(mail=$username)))",
		'sizelimit' => 1,
		'scope' => 'sub'
	);

	unless($searchMesg->code() == Net::LDAP::LDAP_SUCCESS) {
		Carp::carp("Error while finding user $username\n".Dumper($searchMesg));
		
		return undef;
	}

	if($searchMesg->count<=0) {
		Carp::carp("No matching user found for $username");
		
		return undef;
	}
	
	return $searchMesg->entry(0);
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

	# First, get the entry
	my $user = $self->getUser($username,$userDN);
	my $dn = $user->dn();
	$user->changetype('modify');
	$user->replace(
		'userPassword'	=>	$hashedPasswd64,
		'disabledAccount'	=>	'FALSE',
	);

	my $updMesg = $user->update($self->{'ldap'});
	if($updMesg->code() != Net::LDAP::LDAP_SUCCESS) {
		print STDERR $user->ldif();
		
		Carp::carp("Unable to reset user password for $dn\n".Dumper($updMesg));
	}
	return ($updMesg->code() == Net::LDAP::LDAP_SUCCESS) ? $user : undef;
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
	my $user = $self->getUser($username,$userDN);
	my $dn = $user->dn();
	$user->changetype('modify');
	$user->replace(
		'disabledAccount'	=>	($doEnable ? 'FALSE' : 'TRUE'),
	);

	my $updMesg = $user->update($self->{'ldap'});
	if($updMesg->code() != Net::LDAP::LDAP_SUCCESS) {
		print STDERR $user->ldif();
		
		Carp::carp("Unable to ".($doEnable ? 'enable' : 'disable')." user $dn\n".Dumper($updMesg));
	}
	return ($updMesg->code() == Net::LDAP::LDAP_SUCCESS) ? $user : undef;
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
	
	unless($searchMesg->code() == Net::LDAP::LDAP_SUCCESS) {
		Carp::carp("Error while finding users\n".Dumper($searchMesg));
		
		return undef;
	}
	
	return $searchMesg->entries;
}

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
	my $dn = join(',','ou='.$ou,$userDN);
	$entry->dn($dn);
	$entry->add(
		'ou'	=>	$ou,
		'description'	=>	$description,
		'objectClass'	=>	[ 'organizationalUnit' ]
	);
	
	my $updMesg = $entry->update($self->{'ldap'});
	
	if($updMesg->code() != Net::LDAP::LDAP_SUCCESS) {
		print STDERR $entry->ldif();
		
		Carp::carp("Unable to create organizational unit $dn (does the organizational unit already exist?)\n".Dumper($updMesg));
	}
	return $updMesg->code() == Net::LDAP::LDAP_SUCCESS;
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
	
	unless($searchMesg->code() == Net::LDAP::LDAP_SUCCESS) {
		Carp::carp("Error while finding people OUs\n".Dumper($searchMesg));
		
		return undef;
	}
	
	return $searchMesg->entries;
}

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
	foreach my $ownerUID (@{$p_ownerUIDs}) {
		# The owner entry
		my $owner = $self->getUser($ownerUID,$userDN);
		push(@owners,$owner);
		push(@ownersDN,$owner->dn());
	}
	
	# Now, the group of names new entry
	my $entry = Net::LDAP::Entry->new();
	$entry->changetype('modify')  if($doReplace);
	my $dn = join(',','cn='.$cn,$groupDN);
	$entry->dn($dn);
	$entry->add(
		'cn'	=>	$cn,
		'description'	=>	$description,
		'objectClass'	=>	[ 'groupOfNames' ],
		'owner'	=>	\@ownersDN,
		'member'	=>	\@ownersDN
	);
	
	my $updMesg = $entry->update($self->{'ldap'});
	
	if($updMesg->code() != Net::LDAP::LDAP_SUCCESS) {
		print STDERR $entry->ldif();
		
		Carp::carp("Unable to create group of names $dn (does the group of names already exist?)\n".Dumper($updMesg));
		
		return undef;
	}
	
	foreach my $owner (@owners) {
		# And, at last, add the dn to the memberOf list
		$owner->changetype('modify');
		$owner->add('memberOf' => $dn);
		
		$updMesg = $owner->update($self->{'ldap'});
		
		if($updMesg->code() != Net::LDAP::LDAP_SUCCESS) {
			print STDERR $owner->ldif();
			
			Carp::carp("Unable to add memberOf $dn to ".$owner->dn()."\n".Dumper($updMesg));
			
			return undef;
		}
	}
	
	return 1;
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
	
	my $searchMesg = $self->{'ldap'}->search(
		'base' => $groupDN,
		'filter' => "(&(objectClass=groupOfNames)(cn=$groupCN))",
		'sizelimit' => 1,
		'scope' => 'sub'
	);
	
	unless($searchMesg->code() == Net::LDAP::LDAP_SUCCESS) {
		Carp::carp("Error while finding group $groupCN\n".Dumper($searchMesg));
		
		return undef;
	}
	
	if($searchMesg->count<=0) {
		Carp::carp("No matching group found");
		
		return undef;
	}

	# The group entry
	return $searchMesg->entry(0);
}

# Parameters:
#	groupCN: The cn of the groupOfNames to find
#	groupDN: (OPTIONAL) The DN used as parent of this new groupOfNames.
#		If not set, it uses the one read from the configuration file.
# It returns a reference to the array of LDAP entries corresponding to the group members on success
sub getGroupMembers($;$) {
	my $self = shift;
	
	my($groupCN,$groupDN)=@_;
	
	$groupDN = $self->{'groupDN'}  unless(defined($groupDN) && length($groupDN)>0);
	
	my $group = $self->getGroup($groupCN,$groupDN);
	return undef  unless(defined($group));
	
	my @users = ();
	my $p_userDNs = $group->get_value('member',asref => 1);
	foreach my $userDN (@{$p_userDNs}) {
		my $searchMesg = $self->{'ldap'}->search(
			'base' => $userDN,
			'scope' => 'base'
		);
		
		unless($searchMesg->code() == Net::LDAP::LDAP_SUCCESS) {
			Carp::carp("Error while finding user $userDN\n".Dumper($searchMesg));
			
			return undef;
		}
		
		push(@users,$searchMesg->entry(0));
	}
	
	return \@users;
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
	
	unless($searchMesg->code() == Net::LDAP::LDAP_SUCCESS) {
		Carp::carp("Error while finding groups\n".Dumper($searchMesg));
		
		return undef;
	}
	
	return $searchMesg->entries;
}

# Parameters:
#	userUID: The uid of the user to be added to the groupOfNames.
#	p_groupCN: The cn(s) of the groupOfNames where the user must be added
#	userDN: (OPTIONAL) The DN used as parent of all the ou. If not set,
#		it uses the one read from the configuration file.
#	groupDN: (OPTIONAL) The DN used as parent of this new groupOfNames.
#		If not set, it uses the one read from the configuration file.
sub addUserToGroup($$;$$) {
	my $self = shift;
	
	my($userUID,$p_groupCN,$userDN,$groupDN)=@_;
	
	$userDN = $self->{'userDN'}  unless(defined($userDN) && length($userDN)>0);
	$groupDN = $self->{'groupDN'}  unless(defined($groupDN) && length($groupDN)>0);
	
	$p_groupCN = [ $p_groupCN ]  unless(ref($p_groupCN) eq 'ARRAY');
	
	# First, the user must be found
	my $user = $self->getUser($userUID,$userDN);
	return undef  if(!defined($user) || $user->get_value('disabledAccount') eq 'TRUE');
	
	my @newGroupDNs = ();
	
	ADD_USER_GROUPCN:
	foreach my $groupCN (@{$p_groupCN}) {
		# Second, each group of names must be found
		my $group = $self->getGroup($groupCN,$groupDN);
		return undef  unless(defined($group));
		
		# Is the user already in the group?
		my $p_members = $group->get_value('member', 'asref' => 1);
		foreach my $member (@{$p_members}) {
			next ADD_USER_GROUPCN  if($member eq $user->dn());
		}
		
		# Now, add the user dn to the group's member list
		$group->changetype('modify');
		$group->add('member' => $user->dn());
		
		my $updMesg = $group->update($self->{'ldap'});
		
		if($updMesg->code() != Net::LDAP::LDAP_SUCCESS) {
			print STDERR $group->ldif();
			
			Carp::carp("Unable to add member ".$user->dn()." to ".$group->dn()."\n".Dumper($updMesg));
			
			return undef;
		}
		push(@newGroupDNs,$group->dn());
	}
	
	if(scalar(@newGroupDNs) > 0) {
		# And, at last, add the group dn to the user's memberOf list
		$user->changetype('modify');
		$user->add('memberOf' => \@newGroupDNs);
		
		my $updMesg = $user->update($self->{'ldap'});
		
		if($updMesg->code() != Net::LDAP::LDAP_SUCCESS) {
			print STDERR $user->ldif();
			
			Carp::carp("Unable to add memberOf ".join(',',@newGroupDNs)." to ".$user->dn()."\n".Dumper($updMesg));
			
			return undef;
		}
	}
	
	return 1;
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
	my $dn = join(',',$keyName.'='.$keyValue,$parentDN);
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

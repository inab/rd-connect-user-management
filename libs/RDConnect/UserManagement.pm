#!/usr/bin/perl -w

use strict;
use v5.10.1;
use experimental 'smartmatch';

package RDConnect::UserManagement;

use Carp;
use Config::IniFiles;
use Digest;
use MIME::Base64;
use Net::LDAP;
use Net::LDAP::Entry;
use boolean qw();

use constant SECTION	=>	'main';
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
	
	# This one is used to encode passwords in the correct way
	$self->{'digestAlg'} = $cfg->val(SECTION,'digest','SHA-1');

	
	return bless($self,$class);
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
# Array element meaning:	LDAP attribute name, visible attribute on JSON, array attribute on LDAP, method to translate from JSON to LDAP, method to translate from LDAP to JSON
my %JSON_LDAP_USER_ATTRIBUTES = (
	'givenName'	=>	['givenName', boolean::true, boolean::true, undef, undef],
	'surname'	=>	['sn', boolean::true, boolean::true, undef, undef],
	'hashedPasswd64'	=>	['userPassword', boolean::false, boolean::false, sub { return (!defined($_[1]) || IsEncodedPassword($_[1])) ? $_[1] : $_[0]->encodePassword($_[1]);}, undef],
	'username'	=>	['uid',boolean::true, boolean::false, undef, undef],
	'enabled'	=>	['disabledAccount',boolean::true, boolean::false, sub { return ($_[1] ? 'FALSE':'TRUE'); }, sub { return (defined($_[1]) && $_[1] eq 'TRUE'); }],
	'cn'	=>	['cn', boolean::true, boolean::false, undef, undef],
	'email'	=>	['mail',boolean::true, boolean::true, undef, undef],
	
	'employeeType'	=>	['employeeType', boolean::true, boolean::false, undef, undef],
	'title'	=>	['title', boolean::true, boolean::false, undef, undef],
	'jpegPhoto'	=>	['jpegPhoto', boolean::true, boolean::false, undef, undef],
	'telephoneNumber'	=>	['telephoneNumber', boolean::true, boolean::true, undef, undef],
	'facsimileTelephoneNumber'	=>	['facsimileTelephoneNumber', boolean::true, boolean::true, undef, undef],
	'registeredAddress'	=>	['registeredAddress', boolean::true, boolean::false, undef, undef],
	'postalAddress'	=>	['postalAddress', boolean::true, boolean::false, undef, undef],
);

# Inverse correspondence: LDAP attributes to JSON ones
my %LDAP_JSON_USER_ATTRIBUTES = map { $JSON_LDAP_USER_ATTRIBUTES{$_}[0] => [ $_,$JSON_LDAP_USER_ATTRIBUTES{$_}[1..$#{$JSON_LDAP_USER_ATTRIBUTES{$_}}] ] } keys(%JSON_LDAP_USER_ATTRIBUTES);

# Which attributes do we have to mask?
my @JSON_MASK_USER_ATTRIBUTES = ();
foreach my $p_jsonDesc (values(%LDAP_JSON_USER_ATTRIBUTES)) {
	unless($p_jsonDesc->[1]) {
		push(@JSON_MASK_USER_ATTRIBUTES, $p_jsonDesc->[0]);
	}
}

use constant USER_HOTCHPOTCH_ATTRIBUTE	=> 	'jsonData';

my @LDAP_USER_DEFAULT_ATTRIBUTES = (
	'objectClass'	=>	 ['basicRDproperties','inetOrgPerson','top'],
);


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
			
			push(@{$p_err},"Validation errors for not created user $dn\n".join("\n",map { return "\tPath: ".$_->{'path'}.' . Message: '.$_->{'message'}} @valErrors));
		} else {
			# cn normalization
			unless(exists($p_userHash->{'cn'}) && length($p_userHash->{'cn'}) > 0) {
				my $givenName = ref($p_userHash->{'givenName'}) eq 'ARRAY' ? join(' ',@{$p_userHash->{'givenName'}}) : $p_userHash->{'givenName'};
				my $surname = ref($p_userHash->{'surname'}) eq 'ARRAY' ? join(' ',@{$p_userHash->{'surname'}}) : $p_userHash->{'surname'};
				$p_userHash->{'cn'} = $givenName .' '.$surname;
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
				my $ldapVal = defined($JSON_LDAP_USER_ATTRIBUTES{$jsonKey}[3]) ? $JSON_LDAP_USER_ATTRIBUTES{$jsonKey}[3]->($self,$p_userHash->{$jsonKey}) : $p_userHash->{$jsonKey};
				push(@userAttributes,$JSON_LDAP_USER_ATTRIBUTES{$jsonKey}[0] => $ldapVal);
			}
		}
		
		# Last, mask attributes and store the whole JSON in the hotchpotch
		foreach my $jsonKey (@JSON_MASK_USER_ATTRIBUTES) {
			$p_userHash->{$jsonKey} = undef  if(exists($p_userHash->{$jsonKey}));
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
#	p_users: a list of LDAP user objects
# It returns an array of JSON user entries
sub genJSONUsersFromLDAPUsers(\@) {
	my $self = shift;
	
	my($p_users) = @_;
	
	my @retval = ();
	
	my $j = getJSONHandler();
	foreach my $user (@{$p_users}) {
		my $jsonUser = {};
		if($user->exists(USER_HOTCHPOTCH_ATTRIBUTE)) {
			# This could fail, after all
			eval {
				$jsonUser = $j->decode($user->get_value(USER_HOTCHPOTCH_ATTRIBUTE)); 
			};
		}
		
		foreach my $ldapKey (keys(%LDAP_JSON_USER_ATTRIBUTES)) {
			my $ldapDesc = $LDAP_JSON_USER_ATTRIBUTES{$ldapKey};
			
			if($user->exists($ldapKey)) {
				# Only processing those LDAP attributes which are exportable
				if($ldapDesc->[1]) {
					# LDAP attribute values always take precedence over JSON ones
					my @values = $user->get_value($ldapKey);
					@values = $ldapDesc->[4]->($self,@values)  if(defined($ldapDesc->[4]));
					
					$jsonUser->{$ldapDesc->[0]} = $ldapDesc->[2] ? \@values : $values[0];
				} else {
					$jsonUser->{$ldapDesc->[0]} = undef;
				}
			} elsif(exists($jsonUser->{$ldapDesc->[0]})) {
				# Removing spureous key not any valid
				delete($jsonUser->{$ldapDesc->[0]});
			}
		}
		
		push(@retval,$jsonUser);
	}
	
	return \@retval;
}

# Parameters:
#	username: the RD-Connect username or user e-mail
#	p_userHash: a reference to a hash with the modified user information
#	p_removedKeys: a reference to an array with the removed keys
#	userDN: (OPTIONAL) The DN used as parent of this new ou. If not set,
#		it uses the one read from the configuration file.
# It returns the LDAP entry of the user on success
sub modifyJSONUser($\%\@;$) {
	my $self = shift;
	
	my($username,$p_userHash,$p_removedKeys,$userDN) = @_;
	
	my $success = undef;
	my $payload;
	my $payload2;
	
	if(ref($p_userHash) eq 'HASH' && ref($p_removedKeys) eq 'ARRAY') {
		# Getting the user entry to be modified
		my $user;
		($success, $payload, $user) = $self->getJSONUser($username,$userDN);
		
		if($success) {
			my $jsonUser = $payload;
			my $payload = [];
			
			# Now, apply the changes
			my $modifications = undef;
			my @addedLDAPAttributes = ();
			my @modifiedLDAPAttributes = ();
			my @removedLDAPAttributes = ();
			
			# Detect modified attributes
			foreach my $jsonKey (%{$p_userHash}) {
				# Skipping modifications on banned keys
				next  if(exists($JSON_LDAP_USER_ATTRIBUTES{$jsonKey}) && !$JSON_LDAP_USER_ATTRIBUTES{$jsonKey}[1]);
				
				unless(exists($jsonUser->{$jsonKey}) && $p_userHash->{$jsonKey} ~~ $jsonUser->{$jsonKey}) {
					$modifications = 1;
					$jsonUser->{$jsonKey} = $p_userHash->{$jsonKey};
					
					# This is also an LDAP attribute modification
					if(exists($JSON_LDAP_USER_ATTRIBUTES{$jsonKey})) {
						my $value = $p_userHash->{$jsonKey};
						$value = $JSON_LDAP_USER_ATTRIBUTES{$jsonKey}[3]->($self,$value)  if(defined($JSON_LDAP_USER_ATTRIBUTES{$jsonKey}[3]));
						
						if(exists($jsonUser->{$jsonKey})) {
							push(@modifiedLDAPAttributes, $JSON_LDAP_USER_ATTRIBUTES{$jsonKey}[0] => $value);
						} else {
							push(@addedLDAPAttributes, $JSON_LDAP_USER_ATTRIBUTES{$jsonKey}[0] => $value);
						}
					}
				}
			}
			
			foreach my $jsonKey (@{$p_removedKeys}) {
				# Skipping modifications on banned keys
				next  if(exists($JSON_LDAP_USER_ATTRIBUTES{$jsonKey}) && !$JSON_LDAP_USER_ATTRIBUTES{$jsonKey}[1]);
				
				if(exists($jsonUser->{$jsonKey})) {
					$modifications = 1;
					delete($jsonUser->{$jsonKey});
					
					# This is also an LDAP attribute modification
					if(exists($JSON_LDAP_USER_ATTRIBUTES{$jsonKey})) {
						push(@removedLDAPAttributes,$JSON_LDAP_USER_ATTRIBUTES{$jsonKey}[0]);
					}
				}
			}
			
			if($modifications) {
				# Before any modification, let's validate
				my $userVal = getCASUserValidator();
				my @valErrors = $userVal->validate($jsonUser);
				
				if(scalar(@valErrors) > 0) {
					$success = undef;
					
					my $dn = $user->dn();
					
					$payload = [ "Validation errors for modifications on user $dn\n".join("\n",map { return "\tPath: ".$_->{'path'}.' . Message: '.$_->{'message'}} @valErrors) ];
				} else {
					# cn normalization
					unless(exists($p_userHash->{'cn'}) && length($p_userHash->{'cn'}) > 0) {
						my $givenName = ref($p_userHash->{'givenName'}) eq 'ARRAY' ? join(' ',@{$p_userHash->{'givenName'}}) : $p_userHash->{'givenName'};
						my $surname = ref($p_userHash->{'surname'}) eq 'ARRAY' ? join(' ',@{$p_userHash->{'surname'}}) : $p_userHash->{'surname'};
						$p_userHash->{'cn'} = $givenName .' '.$surname;
						
						push(@modifiedLDAPAttributes, $JSON_LDAP_USER_ATTRIBUTES{'cn'}[0] => $p_userHash->{'cn'});
					}
					
					# Mask attributes and store the whole JSON in the hotchpotch
					foreach my $jsonKey (@JSON_MASK_USER_ATTRIBUTES) {
						$p_userHash->{$jsonKey} = undef  if(exists($p_userHash->{$jsonKey}));
					}
					
					my $j = getJSONHandler();
					push(@modifiedLDAPAttributes, USER_HOTCHPOTCH_ATTRIBUTE() => $j->encode($jsonUser));
					
					# Now, let's modify the LDAP entry
					my $dn = $user->dn();
					$user->changetype('modify');
					
					# The batch of modifications
					$user->add(@addedLDAPAttributes)  if(scalar(@addedLDAPAttributes) > 0);
					$user->replace(@modifiedLDAPAttributes)  if(scalar(@modifiedLDAPAttributes) > 0);
					$user->delete(map { $_ => undef; } @removedLDAPAttributes)  if(scalar(@removedLDAPAttributes) > 0);

					my $updMesg = $user->update($self->{'ldap'});
					if($updMesg->code() == Net::LDAP::LDAP_SUCCESS) {
						$payload = $jsonUser;
						$payload2 = $user;
					} else {
						$success = undef;
						print STDERR $user->ldif()  unless(wantarray);
						
						$payload = [ "Could not modify user $dn\n".Dumper($updMesg) ];
					}
				}
			} else {
				# No modification, so give as payload the unmodified $jsonUser
				$payload = $jsonUser;
			}
		}
	} else {
		push(@{$payload},'The input user data to modify must be a hash ref!')  unless(ref($p_userHash) eq 'HASH');
		push(@{$payload},'The removed keys parameter must be an array ref!')  unless(ref($p_removedKeys) eq 'ARRAY');
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
	my($success,$payload) = $self->getUser($username,$userDN);
	if($success) {
		my $user = $payload;
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
#	ou: The short, organizational unit name, which hangs on userDN
#	userDN: (OPTIONAL) The DN used as parent of all the users. If not set,
#		it uses the one read from the configuration file.
sub listPeopleOUUsers($;$) {
	my $self = shift;
	
	my($ou,$userDN) = @_;
	
	$userDN = $self->{'userDN'}  unless(defined($userDN) && length($userDN)>0);
	my $dn = join(',','ou='.$ou,$userDN);
	
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
		
		if($updMesg->code() == Net::LDAP::LDAP_SUCCESS) {
			# Second step, for all the owners, point back
			foreach my $owner (@owners) {
				# And, at last, add the dn to the memberOf list
				$owner->changetype('modify');
				$owner->add('memberOf' => $dn);
				
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
#	groupCN: The cn of the groupOfNames to find
#	groupDN: (OPTIONAL) The DN used as parent of this new groupOfNames.
#		If not set, it uses the one read from the configuration file.
# It returns a reference to the array of LDAP entries corresponding to the group members on success
sub getGroupMembers($;$) {
	my $self = shift;
	
	my($groupCN,$groupDN)=@_;
	
	$groupDN = $self->{'groupDN'}  unless(defined($groupDN) && length($groupDN)>0);
	
	my($success,$group) = $self->getGroup($groupCN,$groupDN);
	return undef  unless($success);
	
	my $payload = [];
	my @users = ();
	my $p_userDNs = $group->get_value('member',asref => 1);
	foreach my $userDN (@{$p_userDNs}) {
		my $searchMesg = $self->{'ldap'}->search(
			'base' => $userDN,
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
	my($success, $payload) = $self->getUser($userUID,$userDN);
	#if($success && $payload->get_value('disabledAccount') eq 'TRUE') {
	#	$success = undef;
	#	$payload = [ 'Cannot modify a disabled user' ];
	#}
	
	if($success) {
		my $user = $payload;
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
			my $p_members = $group->get_value('member', 'asref' => 1);
			foreach my $member (@{$p_members}) {
				next ADD_USER_GROUPCN  if($member eq $user->dn());
			}
			
			push(@newGroups,$group);
		}
		
		if($success && scalar(@newGroups) > 0) {
			my @newGroupDNs = ();
			foreach my $group (@newGroups) {
				# Now, add the user dn to the group's member list
				$group->changetype('modify');
				$group->add('member' => $user->dn());
				
				my $updMesg = $group->update($self->{'ldap'});
				
				if($updMesg->code() != Net::LDAP::LDAP_SUCCESS) {
					$success = undef;
					print STDERR $group->ldif()  unless(wantarray);
					
					push(@{$payload},"Unable to add member ".$user->dn()." to ".$group->dn()."\n".Dumper($updMesg));
					last;
				}
				push(@newGroupDNs,$group->dn());
			}
			
			if($success) {
				@newGroups = ();
				
				# And, at last, add the group dn to the user's memberOf list
				$user->changetype('modify');
				$user->add('memberOf' => \@newGroupDNs);
				
				my $updMesg = $user->update($self->{'ldap'});
				
				if($updMesg->code() != Net::LDAP::LDAP_SUCCESS) {
					$success = undef;
					print STDERR $user->ldif();
					
					push(@{$payload},"Unable to add memberOf ".join(',',@newGroupDNs)." to ".$user->dn()."\n".Dumper($updMesg));
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

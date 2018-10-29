#!/usr/bin/perl
# RD-Connect User Management Libraries
# José María Fernández (jose.m.fernandez@bsc.es)

use strict;
use warnings 'all';

use Data::Password::zxcvbn;

use RDConnect::UserManagement;
use RDConnect::MailManagement;
use RDConnect::TemplateManagement;
use RDConnect::RequestManagement;

package RDConnect::MetaUserManagement;

use Scalar::Util qw(blessed);



# These are the default templates
BEGIN {

	use constant NewUserDomain	=>	'newUserTemplates';
	my $DEFAULT_newUserTemplate = <<'EOF' ;
Dear [% fullname %],
        your RD-Connect username is [% username %]. Following the changes in the european GDPR, you must accept
        the code of conduct of RD-Connect. In the meanwhile, your account will be disabled.

        Next link (valid until [% expirationlink %]) will mark your acceptance of RD-Connect code of conduct.

[% gdprlink %]

        If you need to reset your password, please follow next link:

[% passresetlink %]

        Best,
                The RD-Connect team
EOF

	use constant ChangedPasswordDomain	=>	'changedPasswordTemplates';
	my $DEFAULT_firstPassMailTemplate = <<'EOF' ;
Your RD-Connect password has just been resetted to [% password %].

Kind Regards,
	RD-Connect team
EOF

	use constant ResettedPasswordDomain	=>	'resettedPasswordTemplates';
	my $DEFAULT_passResetMailTemplate = <<'EOF' ;
Your RD-Connect password has just been resetted.

If you want to reset it again, please follow next link: [% passresetlink %]

Kind Regards,
	RD-Connect team
EOF
	
	# We add them here
	RDConnect::TemplateManagement::AddMailTemplatesDomains(
		{
			'apiKey' => 'newUser',
			'desc' => 'New user creation templates',
			'tokens' => [ 'username', 'fullname', 'gdprlink', 'expirationlink', 'passresetlink', 'unique' ],
			'ldapDomain' => NewUserDomain(),
			'cn' =>	'mailTemplate.html',
			'ldapDesc' => 'New User Mail Template',
			'defaultTitle' => 'RD-Connect platform portal user creation [[% unique %]]',
			'default' => $DEFAULT_newUserTemplate
		},
		#{
		#	'apiKey' => 'passTemplate',
		#	'desc' => 'New password templates',
		#	'tokens' => [ 'password', 'unique' ],
		#	'ldapDomain' => ChangedPasswordDomain(),
		#	'cn' =>	'changedPassMailTemplate.html',
		#	'ldapDesc' => 'Changed password mail template',
		#	'defaultTitle' => 'RD-Connect platform portal user creation [[% unique %]]',
		#	'default' => $DEFAULT_firstPassMailTemplate
		#},
		{
			'apiKey' => 'resettedPassTemplate',
			'desc' => 'Resetted password templates',
			'tokens' => [ 'passresetlink', 'unique' ],
			'ldapDomain' => ResettedPasswordDomain(),
			'cn' =>	'resettedPassMailTemplate.html',
			'ldapDesc' => 'Resetted password mail template',
			'defaultTitle' => 'RD-Connect platform portal password changed [[% unique %]]',
			'default' => $DEFAULT_passResetMailTemplate
		},
	);
}



# Parameters:
#	iParam: Either a RDConnect::TemplateManagement or RDConnect::RequestManagement instance
sub new($$) {
	my $self = shift;
	my $class = ref($self) || $self;
	
	$self = {}  unless(ref($self));
	
	my $iParam = shift;
	
	my $bself = bless($self,$class);
	
	if(blessed($iParam)) {
		if($iParam->isa('RDConnect::TemplateManagement')) {
			$self->{'_tMgmt'} = $iParam;
			$self->{'_rMgmt'} = RDConnect::RequestManagement->new($iParam);
			
		} elsif($iParam->isa('RDConnect::RequestManagement')) {
			$self->{'_rMgmt'} = $iParam;
			$self->{'_tMgmt'} = $self->{'_rMgmt'}->getTemplateManagementInstance();
		}
		$self->{'_rMgmt'}->setMetaUserManagementInstance($bself);
	}
	
	$self->{'_uMgmt'} = $self->{'_tMgmt'}->getUserManagementInstance();
	$self->{'_cfg'} = $self->{'_uMgmt'}->getCfg();
	
	return $bself;
}


sub getUserManagementInstance() {
	return $_[0]->{'_uMgmt'};
}

sub getTemplateManagementInstance() {
	return $_[0]->{'_tMgmt'};
}

sub getRequestManagementInstance() {
	return $_[0]->{'_rMgmt'};
}

sub getCfg() {
	return $_[0]->{'_cfg'};
}


use constant APGSECTION	=>	'apg';

sub getRandomPassword() {
	my $self = shift;
	
	my $cfg = $self->getCfg();
	
	my $apgPath = $cfg->val(APGSECTION,'apgPath','apg');
	my $apgMin = $cfg->val(APGSECTION,'min-length',12);
	my $apgMax = $cfg->val(APGSECTION,'max-length',16);
	
	my @apgParams = ($apgPath,'-m',$apgMin,'-x',$apgMax,'-c','/dev/urandom','-n',1,'-q');
	
	my $pass = undef;
	# my $apgCall = join(' ',@apgParams);
	# 
	# $pass = `$apgCall`;
	# 
	if(open(my $APG,'-|',@apgParams)) {
		$pass = <$APG>;
		chomp($pass);
		close($APG);
	} else {
		return bless({'reason' => 'Unable to generate a random password','trace' => $!,'code' => 500},'RDConnect::MetaUserManagement::Error');
	}
	
	return $pass;
}

sub getMailManagementInstance($$\%;\@) {
	my $self = shift;
	
	my($mailTemplate,$p_keyvals,$p_attachmentFiles) = @_;
	
	my $cfg = $self->getCfg();
	
	# Mail configuration parameters
	return RDConnect::MailManagement->new($cfg,$mailTemplate,$p_keyvals,$p_attachmentFiles);
}

sub createUser(\[%@];$) {
	my $self = shift;
	
	my($p_newUsers,$NOEMAIL) = @_;
	
	my $tMgmt = $self->getTemplateManagementInstance();
	my $uMgmt = $self->getUserManagementInstance();
	my $cfg = $uMgmt->getCfg();
	
	# Before any task
	# Getting the mailTemplate and the attachments for new user creation
	my $mailTemplate;
	my $mailTemplateTitle;
	my @attachmentFiles = ();
	
	unless($NOEMAIL) {
		($mailTemplate,$mailTemplateTitle,@attachmentFiles) = $tMgmt->fetchEmailTemplate(NewUserDomain());
		
		# Return if error condition
		return $mailTemplate  if(blessed($mailTemplate));
	}
	
	$p_newUsers = [ $p_newUsers ]  if(ref($p_newUsers) eq 'HASH');
	
	my @errorStack = ();
	foreach my $p_newUser (@{$p_newUsers}) {
		my $userPassword;
		if(exists($p_newUser->{'userPassword'})) {
			$userPassword = $p_newUser->{'userPassword'};
		} else {
			$userPassword = $self->getRandomPassword();
			return $userPassword  if(blessed($userPassword));
			$p_newUser->{'userPassword'} = $userPassword;
		}
		
		my($success,$payload,$p_users) = $uMgmt->createExtUser($p_newUser);
		
		if($success) {
			my $user = $p_users->[0];
			my $createdJsonUser = $payload->[0];
			my $username = $createdJsonUser->{'username'};
			unless($NOEMAIL) {
				my $unique = time;
				
				my $rMgmt = $self->getRequestManagementInstance();
				my($passresetlink) = $rMgmt->genLinksFromReq(RDConnect::RequestManagement::STATIC_PASSWORD_RESET_REQ_ID(),'');
				my %keyval1 = (
					'username' => '(undefined)',
					'fullname' => '(undefined)',
					'gdprlink' => '(undefined)',
					'expirationlink' => '(undefined)',
					'passresetlink' => $passresetlink,
					'unique' => $unique
				);
				
				# Mail configuration parameters
				my $mail1 = $self->getMailManagementInstance($mailTemplate,\%keyval1,\@attachmentFiles);
				$mail1->setSubject($mailTemplateTitle);
				
				my $fullname = $createdJsonUser->{'cn'};
				my $email = $createdJsonUser->{'email'}[0];
				my $to = Email::Address->new($fullname => $email);
				
				$keyval1{'username'} = $username;
				$keyval1{'fullname'} = $fullname;
				eval {
					my($requestLink,$desistLink,$expiration) = $self->createGDPRValidationRequest($username);
					if(blessed($requestLink)) {
						print
					}
					
					$keyval1{'gdprlink'} = $requestLink;
					$keyval1{'expirationlink'} = $expiration;
					
					$mail1->sendMessage($to,\%keyval1);
					
					# Sending the password reset request
					$self->createPasswordResetRequest($username);
					
					# And the e-mail validation requests
					$self->sendCheckEMailRequests($createdJsonUser);
				};
				
				if($@) {
					push(@errorStack,{'reason' => 'Error while sending user e-mail','trace' => $@,'code' => 500});
				}
			} else {
				print $NOEMAIL "$username\t$userPassword\n";
			}
		} else {
			push(@errorStack,{'reason' => 'Error while creating user','trace' => $payload,'code' => 500});
		}
		
		#send_file(\$data, content_type => 'image/jpeg');
	}

	if(scalar(@errorStack) > 0) {
		return scalar(@errorStack) > 1 ? bless({'reason' => 'Multiple errors','trace' => \@errorStack,'code' => 500},'RDConnect::MetaUserManagement::Error') : bless($errorStack[0],'RDConnect::MetaUserManagement::Error');
	} else {
		return undef;
	}
}

# This method is called from the API and command-line when a password is being changed
sub resetUserPassword($$) {
	my $self = shift;
	
	my($userId,$userPassword) = @_;
	
	my $cfg = $self->getCfg();
	my $tMgmt = $self->getTemplateManagementInstance();
	my $uMgmt = $self->getUserManagementInstance();
	
	if(defined($userPassword)) {
		# Now, let's check the strength of the input password
		my $evPass = Data::Password::zxcvbn::password_strength($userPassword);
		return bless({'reason' => 'Password is too weak','trace' => $evPass,'code' => 400},'RDConnect::MetaUserManagement::Error')  if($evPass->{'score'} < 3);
	} else {
		$userPassword = $self->getRandomPassword();
		return $userPassword  if(blessed($userPassword));
	}
	
	my($passMailTemplate,$passMailTemplateTitle,@passAttachmentFiles) = $tMgmt->fetchEmailTemplate(ResettedPasswordDomain());
	
	return $passMailTemplate  if(blessed($passMailTemplate));
	
	my($success,$payload) = $uMgmt->getUser($userId);
	
	my $user;
	if($success) {
		$user = $payload;
		($success,$payload) = $uMgmt->resetUserPassword($userId,$userPassword);
	}
	
	my $retval = undef;
	
	if($success) {
		my $unique = time;

		my $rMgmt = $self->getRequestManagementInstance();
		my($passresetlink) = $rMgmt->genLinksFromReq(RDConnect::RequestManagement::STATIC_PASSWORD_RESET_REQ_ID(),'');
		
		my %keyval2 = ( 'passresetlink' => $passresetlink, 'unique' => $unique );

		# Sending a reminder about e-mail addresses
		$self->sendUsernameEMailRequests($userId);
		
		# Sending a reminder about GDPR acceptance
		unless($uMgmt->didUserAcceptGDPR($user)) {
			my($requestLink,$desistLink,$expiration) = $self->createGDPRValidationRequest($userId);
		}
		
		# Mail configuration parameters
		my $mail2 = $self->getMailManagementInstance($passMailTemplate,\%keyval2,\@passAttachmentFiles);
		$mail2->setSubject($passMailTemplateTitle);
		
		my $username = $payload->{'username'};
		my $fullname = $payload->{'cn'};
		my $email = $payload->{'email'}[0];
		my $to = Email::Address->new($fullname => $email);
		
		eval {
			$mail2->sendMessage($to,\%keyval2);
		};
		if($@) {
			return bless({'reason' => 'Error while sending password change e-mail','trace' => $@,'code' => 500},'RDConnect::MetaUserManagement::Error');
		}
	} else {
		$retval = bless({'reason' => 'Error while resetting user password for user '.$userId,'trace' => $payload,'code' => 500},'RDConnect::MetaUserManagement::Error');
	}
	
	#send_file(\$data, content_type => 'image/jpeg');
	return $retval;
}

sub sendCheckEMailRequests(\%) {
	my $self = shift;

	my($storedJsonUser) = @_;
	
	# Now, let's check whether there are e-mail addresses to be revalidated
	if(exists($storedJsonUser->{'registeredEmails'}) && ref($storedJsonUser->{'registeredEmails'}) eq 'ARRAY') {
		my $curr_epoch = RDConnect::UserManagement::_epoch_ISO8601_RFC3339(time());
		# The username could have changed
		my $theUsername = $storedJsonUser->{'username'};
		
		my $wasModified = undef;
		foreach my $eEntry (@{$storedJsonUser->{'registeredEmails'}}) {
			# Has the e-mail to be (re-)checked?
			if($eEntry->{'status'} eq 'unchecked' || ($eEntry->{'status'} eq 'checked' && $eEntry->{'validUntil'} lt $curr_epoch)) {
				$wasModified = 1;
				$self->createConfirmEMailRequest($theUsername,$eEntry->{'email'});
			}
		}
		
		# As the user entry could have been changed, re-get it
		if($wasModified) {
			my $uMgmt = $self->getUserManagementInstance();
			(undef,$storedJsonUser) = $uMgmt->getJSONUser($theUsername);
		}
	}
	
	return $storedJsonUser;
}

sub sendUsernameEMailRequests($) {
	my $self = shift;

	my($username) = @_;
	
	my $uMgmt = $self->getUserManagementInstance();
	my($success,$jsonUser) = $uMgmt->getJSONUser($username);
	if($success) {
		# And check e-mail validity
		return $self->sendCheckEMailRequests($jsonUser);
	}
	
	return undef;
}

# This methods modifies an user, and it also creates e-mail validation whenever
# it detects an e-mail has not been validated yet
# Parameters:
#	username: the username to receive the modifications
#	p_jsonUser: The JSON user data representation, to be updated
# It returns a tuple of (success,modified entry)
sub modifyUser($\%) {
	my $self = shift;
	
	my($username, $p_jsonUser) = @_;
	
	my $uMgmt = $self->getUserManagementInstance();
	
	my($success,$storedJsonUser) = $uMgmt->modifyJSONUser($username,$p_jsonUser);
	
	# Now, let's check whether there are e-mail addresses to be revalidated
	if($success) {
		$storedJsonUser = $self->sendCheckEMailRequests($storedJsonUser);
	}
	
	return ($success,$storedJsonUser);
}


####################
# Requests creation #
######################

# Request creation, with e-mail
# Parameters:
#	requestType: one of the accepted types
#	publicPayload: the payload to be sent to the view
#	ttl: if set, the number of seconds until the request expires
#	who: if set, the user who requested this operation. undef on internal origin
#	targetNS: what kind of entry is going to be created/manipulated
#	targetId: if defined, which entry is going to be manipulated
#	referringDN: if set, the full dn of the entry to be manipulated
# It returns true on success
sub createMetaRequest($\[@%]$$$;$$) {
	my $self = shift;
	
	my($requestType,$publicPayload,$ttl,$who,$targetNS,$targetId,$referringDN) = @_;
	
	my $uMgmt = $self->getUserManagementInstance();
	my $tMgmt = $self->getTemplateManagementInstance();
	my $rMgmt = $self->getRequestManagementInstance();
	
	# Colleting the addresses for the template
	my $p_addresses = [];
	my $username = undef;
	my $fullname = undef;
	
	my $targetWho = $who;
	$targetWho = $targetId  if(!defined($targetWho) && $targetNS eq 'user');

	unless(defined($targetWho)) {
		# TODO: default addresses???
	}

	if(defined($targetWho)) {
		my($success,$jsonUser) = $uMgmt->getJSONUser($targetWho);
		$p_addresses = $tMgmt->getEmailAddressesFromJSONUser($jsonUser);
		$username = $jsonUser->{'username'};
		$fullname = $jsonUser->{'cn'};
	}
	
	# At least one e-mail is needed
	if(scalar(@{$p_addresses}) > 0) {
		# The request has been created
		my($requestId,$desistCode,$expiration) = $uMgmt->createRequest(
			$requestType,
			$publicPayload,
			$ttl,
			$who,
			$targetNS,
			$targetId,
			$referringDN
		);
		
		if(defined($requestId)) {
			# Create the links
			my($requestlink,$desistlink) = $rMgmt->genLinksFromReq($requestId,$desistCode);
			
			my $unique = time;
			my %keyval = (
				'username'	=>	$username,
				'fullname'	=>	$fullname,
				'requestlink'	=>	$requestlink,
				'desistlink'	=>	$desistlink,
				'expiration'	=>	$expiration,
				'unique'	=>	$unique,
			);
			
			# Add the publicPayload keys and values
			# so it is extensible
			@keyval{keys(%{$publicPayload})} = values(%{$publicPayload});
			
			# Get the template to be used
			my($mailTemplate,$mailTemplateTitle,@attachmentFiles) = $tMgmt->fetchEmailTemplateByRequestType($requestType);
			return $mailTemplate  if(blessed($mailTemplate));

			# And the accessory ones to be injected, described in 'deps'
			my $tStruct = $tMgmt->mailTemplateStructureByRequestType($requestType);
			if(exists($tStruct->{'deps'})) {
				while(my($tKey,$tDomainId) = each(%{$tStruct->{'deps'}})) {
					# These values are already stored in the LDAP directory
					# as templates (although they are not)
					my($tValue,undef,@tAttachmentFiles) = $tMgmt->fetchEmailTemplate($tDomainId);
					return $tValue  if(blessed($tValue));
					
					# Set the value
					$keyval{$tKey} = ${$tValue->{'content'}};
					# and add the associated attachments
					push(@attachmentFiles,@tAttachmentFiles)  if(scalar(@tAttachmentFiles) > 0);
				}
			}
			
			
			# Now, let's send all the e-mails
			my $mail = $self->getMailManagementInstance($mailTemplate,\%keyval,\@attachmentFiles);
			$mail->setSubject($mailTemplateTitle);
			
			foreach my $email (@{$p_addresses}) {
				my $to = Email::Address->new($fullname => $email);
				eval {
					$mail->sendMessage($to,\%keyval);
				};
				
				if($@) {
					return bless({'reason' => 'Error while sending request e-mail','trace' => $@,'code' => 500},'RDConnect::MetaUserManagement::Error');
				}
			}
			
			# If all has gone properly, we get this
			return ($requestlink,$desistlink,$expiration);
		} else {
			return bless({'reason' => 'Error while creating request','trace' => $desistCode,'code' => 500},'RDConnect::MetaUserManagement::Error');
		}
		
	} else {
		return bless({'reason' => 'No e-mail address is available','code' => 500},'RDConnect::MetaUserManagement::Error');
	}
	
}

# Create a password reset request:
# Parameters:
#	usernameOrEmail: a username or e-mail of a potential user
# It returns the same as createMetaRequest on success, undef otherwise
sub createPasswordResetRequest($) {
	my $self = shift;
	
	my($usernameOrEmail) = @_;
	my $uMgmt = $self->getUserManagementInstance();
	
	# Does the user exist?
	my($success,$jsonUser,$ldapUser) = $uMgmt->getJSONUser($usernameOrEmail);
	
	# As the user was found, let's create the request and send the e-mail
	if($success) {
		# The public payload is prepared
		my $publicPayload = {
			'cn'	=>	$jsonUser->{'cn'},
			'username'	=>	$jsonUser->{'username'},
		};
		
		return $self->createMetaRequest(
			RDConnect::RequestManagement::REQ_PASSWORD_RESET(),
			$publicPayload,
			RDConnect::RequestManagement::DEFAULT__PASSWORD_RESET_TIMEOUT(),
			$jsonUser->{'username'},
			'user',
			$jsonUser->{'username'},
			$ldapUser->dn()
		);
	}
	
	return undef;
}

# Create a GDPR validation request:
# Parameters:
#	usernameOrEmail: a username or e-mail of a user who must accept GDPR
# It returns the same as createMetaRequest on success, undef otherwise
sub createGDPRValidationRequest($) {
	my $self = shift;
	
	my($usernameOrEmail) = @_;
	my $uMgmt = $self->getUserManagementInstance();
	
	# Does the user exist?
	my($success,$jsonUser,$ldapUser) = $uMgmt->getJSONUser($usernameOrEmail);
	
	# As the user was found, let's create the request and send the e-mail
	if($success) {
		# Resetting the GDPR state of the user
		my $encodedToken = undef;
		($success,$encodedToken) = $uMgmt->generateGDPRHashFromUser($ldapUser);
		if($success) {
			# Fetching the current text of the GDPR body
			my $tMgmt = $self->getTemplateManagementInstance();
			my($GDPRtext) = $tMgmt->fetchEmailTemplate(RDConnect::RequestManagement::GDPRTextDomain());
			return (undef,$GDPRtext)  if(blessed($GDPRtext));
			# The public payload is prepared
			my $publicPayload = {
				'cn'	=>	$jsonUser->{'cn'},
				'username'	=>	$jsonUser->{'username'},
				'GDPRtext'	=>	${$GDPRtext->{'content'}},
				'GDPRtoken'	=>	$encodedToken
			};
			
			return $self->createMetaRequest(
				RDConnect::RequestManagement::REQ_ACCEPT_GDPR(),
				$publicPayload,
				RDConnect::RequestManagement::DEFAULT__ACCEPT_GDPR_TIMEOUT(),
				undef,
				'user',
				$jsonUser->{'username'},
				$ldapUser->dn()
			);
		}
	}
	
	return undef;
}

# Create an e-mail validation confirmation request:
# Parameters:
#	usernameOrEmail: a username or e-mail of a user who must accept GDPR
#	emailToConfirm: The e-mail address to be confirmed
#	quarantineDays: The grace period, in days, until the request is discarded
# It returns the same as createMetaRequest on success, undef otherwise
sub createConfirmEMailRequest($$;$) {
	my $self = shift;
	
	my($usernameOrEmail,$emailToConfirm,$quarantineDays) = @_;
	$quarantineDays = RDConnect::UserManagement::DEFAULT__QUARANTINE_DAYS_TIMEOUT()  unless(defined($quarantineDays));
	my $quarantineSeconds = $quarantineDays * 86400;
	
	my $uMgmt = $self->getUserManagementInstance();
	
	# Does the user exist?
	my($success,$jsonUser,$ldapUser) = $uMgmt->getJSONUser($usernameOrEmail);
	
	# As the user was found, let's create the request and send the e-mail
	if($success) {
		$success = $uMgmt->putUserEMailOnValidation($ldapUser,$jsonUser,$emailToConfirm,$quarantineDays);
		if($success) {
			# The public payload is prepared
			my $publicPayload = {
				'cn'	=>	$jsonUser->{'cn'},
				'username'	=>	$jsonUser->{'username'},
				'emailToConfirm'	=>	$emailToConfirm,
			};
			
			return $self->createMetaRequest(
				RDConnect::RequestManagement::REQ_EMAIL_CONFIRM(),
				$publicPayload,
				$quarantineSeconds,
				undef,
				'user',
				$jsonUser->{'username'},
				$ldapUser->dn()
			);
		}
	}
	
	return undef;
}

1;

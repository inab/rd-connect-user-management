#!/usr/bin/perl
# RD-Connect User Management REST API
# José María Fernández (jmfernandez@cnio.es)

use strict;
use warnings 'all';

package RDConnect::MetaUserManagement;

use RDConnect::UserManagement;
use RDConnect::MailManagement;

use constant APGSECTION	=>	'apg';

sub GetRandomPassword($) {
	my($cfg) = @_;
	
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
		return {'reason' => 'Unable to generate a random password','trace' => $!,'code' => 500};
	}
	
	return $pass;
}

sub GetMailManagementInstance($$\%;\@) {
	my($cfg,$mailTemplate,$p_keyvals,$p_attachmentFiles) = @_;
	
	# Mail configuration parameters
	return RDConnect::MailManagement->new($cfg,$mailTemplate,$p_keyvals,$p_attachmentFiles);
}

sub FetchEmailTemplate($$) {
	my($uMgmt,$domainId) = @_;
	
	my($successMail,$payloadMail) = $uMgmt->listJSONDocumentsFromDomain($domainId);
	
	if($successMail) {
		# Now, let's fetch
		my $mailTemplate;
		my @attachmentFiles = ();
		
		if(ref($payloadMail) eq 'ARRAY') {
			foreach my $mailTemplateMetadata (@{$payloadMail}) {
				if(exists($mailTemplateMetadata->{'documentClass'}) && ($mailTemplateMetadata->{'documentClass'} eq 'mailTemplate' || $mailTemplateMetadata->{'documentClass'} eq 'mailAttachment')) {
					# Fetching the document
					my($successT,$payloadT) = $uMgmt->getDocumentFromDomain($domainId,$mailTemplateMetadata->{'cn'});
					
					unless($successT) {
						return {'reason' => 'Mail templates not found','trace' => $payloadT,'code' => 404};
					} elsif(!defined($payloadT)) {
						return {'reason' => 'Mail templates do not have document '.$mailTemplateMetadata->{'cn'},'code' => 404};
					}
					
					# Here the payload is the document
					my $data = $payloadT->get_value('content');
					my $mime = $payloadT->get_value('mimeType');
					my $preparedMime = {
						'content' => \$data,
						'mime' => $mime
					};
					if($mailTemplateMetadata->{'documentClass'} eq 'mailTemplate') {
						$mailTemplate = $preparedMime;
					} else {
						push(@attachmentFiles,$preparedMime);
					}
				}
			}
		}
		
		unless(defined($mailTemplate)) {
			return {'reason' => 'Error while fetching mail templates from domain '.$domainId,'trace' => $payloadMail,'code' => 500};
		}
		
		return ($mailTemplate,@attachmentFiles);
	} else {
		return {'reason' => 'Error while fetching mail templates from domain '.$domainId,'trace' => $payloadMail,'code' => 500};
	}
}

sub NewUserEmailTemplate($) {
	my($uMgmt) = @_;
	
	return FetchEmailTemplate($uMgmt,RDConnect::UserManagement::NewUserDomain);
}


my $DEFAULT_passMailTemplate = <<'EOF' ;
The automatically generated password is  [% password %]  (including any punctuation mark it could contain).

You should change this password by a different one as soon as possible.

Kind Regards,
	RD-Connect team
EOF

sub ChangedPasswordEmailTemplate($) {
	my($uMgmt) = @_;
	
	my @retval = FetchEmailTemplate($uMgmt,RDConnect::UserManagement::ChangedPasswordDomain);
	
	if(ref($retval[0]) eq 'HASH') {
		# Side effect, initialize changed password email template
		# First, get/create the domain
		$uMgmt->getDomain(RDConnect::UserManagement::ChangedPasswordDomain,1);
		$uMgmt->attachDocumentForDomain(
			RDConnect::UserManagement::ChangedPasswordDomain,
			{
				'cn' =>	'changedPassMailTemplate.html',
				'description' => 'Changed password mail template',
				'documentClass' => 'mailTemplate',
			},
			$DEFAULT_passMailTemplate
		);
		
		# Last, set the return value
		@retval = (\$DEFAULT_passMailTemplate);
	}
	
	return @retval;
}


sub CreateUser($\[%@];$) {
	my($uMgmt,$p_newUsers,$NOEMAIL) = @_;
	
	my $cfg = $uMgmt->getCfg();
	
	# Before any task
	# Getting the mailTemplate and the attachments for new user creation
	my $mailTemplate;
	my @attachmentFiles = ();
	
	my $passMailTemplate;
	my @passAttachmentFiles = ();
	
	unless($NOEMAIL) {
		($mailTemplate,@attachmentFiles) = NewUserEmailTemplate($uMgmt);
		
		# Return if error condition
		return $mailTemplate  if(ref($mailTemplate) eq 'HASH');
		
		($passMailTemplate,@passAttachmentFiles) = ChangedPasswordEmailTemplate($uMgmt);
	}
	
	$p_newUsers = [ $p_newUsers]  if(ref($p_newUsers) eq 'HASH');
	
	my @errorStack = ();
	foreach my $p_newUser (@{$p_newUsers}) {
		my $userPassword;
		if(exists($p_newUser->{'userPassword'})) {
			$userPassword = $p_newUser->{'userPassword'};
		} else {
			$userPassword = GetRandomPassword($cfg);
			return $userPassword  if(ref($userPassword));
			$p_newUser->{'userPassword'} = $userPassword;
		}
		
		my($success,$payload,$p_users) = $uMgmt->createExtUser($p_newUser);
		
		if($success) {
			my $user = $p_users->[0];
			my $username = $payload->[0]{'username'};
			unless($NOEMAIL) {
				my %keyval1 = ( 'username' => '(undefined)', 'fullname' => '(undefined)', 'gdprtoken' => '(undefined)' );
				my %keyval2 = ( 'password' => '(undefined)' );
				
				# Mail configuration parameters
				my $unique = time;
				my $mail1 = GetMailManagementInstance($cfg,$mailTemplate,%keyval1,@attachmentFiles);
				$mail1->setSubject($mail1->getSubject().' (I) ['.$unique.']');
				
				my $mail2 = GetMailManagementInstance($cfg,$passMailTemplate,%keyval2,@passAttachmentFiles);
				$mail2->setSubject($mail2->getSubject().' (II) ['.$unique.']');
				
				my $fullname = $payload->[0]{'cn'};
				my $email = $payload->[0]{'email'}[0];
				my $to = Email::Address->new($fullname => $email);
				
				$keyval1{'username'} = $username;
				$keyval1{'fullname'} = $fullname;
				$keyval1{'gdprtoken'} = $uMgmt->generateGDPRHashFromUser($user);
				eval {
					$mail1->sendMessage($to,\%keyval1);
					
					$keyval2{'password'} = $userPassword;
					eval {
						$mail2->sendMessage($to,\%keyval2);
					};
					if($@) {
						push(@errorStack,{'reason' => 'Error while sending password e-mail','trace' => $@,'code' => 500});
					}
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
		return scalar(@errorStack) > 1 ? {'reason' => 'Multiple errors','trace' => \@errorStack,'code' => 500} : $errorStack[0];
	} else {
		return undef;
	}
}

sub ResetUserPassword($$$) {
	my($uMgmt,$userId,$userPassword) = @_;
	
	my $cfg = $uMgmt->getCfg();
	
	my($mailTemplate,@attachmentFiles) = NewUserEmailTemplate($uMgmt);
	
	unless(defined($userPassword)) {
		$userPassword = GetRandomPassword($cfg);
		return $userPassword  if(ref($userPassword));
	}

	my($passMailTemplate,@passAttachmentFiles) = ChangedPasswordEmailTemplate($uMgmt);
	
	my($success,$payload) = $uMgmt->resetUserPassword($userId,$userPassword);
	
	my $retval = undef;
	
	if($success) {
		my %keyval1 = ( 'username' => '(undefined)', 'fullname' => '(undefined)' );
		my %keyval2 = ( 'password' => '(undefined)' );
		
		# Mail configuration parameters
		my $unique = time;
		my $mail1 = GetMailManagementInstance($cfg,$mailTemplate,%keyval1,@attachmentFiles);
		$mail1->setSubject($mail1->getSubject().' (resetted) ['.$unique.']');
		
		my $mail2 = GetMailManagementInstance($cfg,$passMailTemplate,%keyval2,@passAttachmentFiles);
		$mail2->setSubject('RD-Connect password reset for user '.$userId.' ['.$unique.']');
		
		my $username = $payload->{'username'};
		my $fullname = $payload->{'cn'};
		my $email = $payload->{'email'}[0];
		my $to = Email::Address->new($fullname => $email);
		
		$keyval1{'username'} = $username;
		$keyval1{'fullname'} = $fullname;
		eval {
			$mail1->sendMessage($to,\%keyval1);
			
			$keyval2{'password'} = $userPassword;
			eval {
				$mail2->sendMessage($to,\%keyval2);
			};
			if($@) {
				return {'reason' => 'Error while sending password e-mail','trace' => $@,'code' => 500};
			}
		};
		
		if($@) {
			return {'reason' => 'Error while sending user e-mail','trace' => $@,'code' => 500};
		}
	} else {
		$retval = {'reason' => 'Error while resetting user password for user '.$userId,'trace' => $payload,'code' => 500};
	}
	
	#send_file(\$data, content_type => 'image/jpeg');
	return $retval;
}

1;

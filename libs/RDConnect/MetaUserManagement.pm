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
	
	my @apgParams = ($apgPath,'-m',$apgMin,'-x',$apgMax,'-n',1,'-q');
	
	my $pass;
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

sub CreateUser($\[%@];$) {
	my($uMgmt,$p_newUsers,$NOEMAIL) = @_;
	
	my $cfg = $uMgmt->getCfg();
	
	# Before any task
	# Getting the mailTemplate and the attachments for new user creation
	my($successMail,$payloadMail);
	($successMail,$payloadMail) = $uMgmt->listJSONDocumentsFromDomain(RDConnect::UserManagement::NewUserDomain)  unless($NOEMAIL);
	if($NOEMAIL || $successMail) {
		# Now, let's fetch
		my $mailTemplate;
		my @attachmentFiles = ();
		
		# Do not do this when there is no e-mail
		unless($NOEMAIL) {
			if(ref($payloadMail) eq 'ARRAY') {
				foreach my $mailTemplateMetadata (@{$payloadMail}) {
					if(exists($mailTemplateMetadata->{'documentClass'}) && ($mailTemplateMetadata->{'documentClass'} eq 'mailTemplate' || $mailTemplateMetadata->{'documentClass'} eq 'mailAttachment')) {
						# Fetching the document
						my($successT,$payloadT) = $uMgmt->getDocumentFromDomain(RDConnect::UserManagement::NewUserDomain,$mailTemplateMetadata->{'cn'});
						
						unless($successT) {
							return {'reason' => 'Mail templates not found','trace' => $payloadT,'code' => 404};
						} elsif(!defined($payloadT)) {
							return {'reason' => 'Mail templates do not have document '.$mailTemplateMetadata->{'cn'},'code' => 404};
						}
						
						# Here the payload is the document
						my $data = $payloadT->get_value('content');
						if($mailTemplateMetadata->{'documentClass'} eq 'mailTemplate') {
							$mailTemplate = \$data;
						} else {
							push(@attachmentFiles,\$data);
						}
					}
				}
			}
			
			unless(defined($mailTemplate)) {
				return {'reason' => 'Error while fetching mail templates in order to create user','trace' => $payloadMail,'code' => 500};
			}
		}
		
		$p_newUsers = [ $p_newUsers]  if(ref($p_newUsers) eq 'HASH');
		
		foreach my $p_newUser (@{$p_newUsers}) {
			my $userPassword;
			if(exists($p_newUser->{'userPassword'})) {
				$userPassword = $p_newUser->{'userPassword'};
			} else {
				$userPassword = GetRandomPassword($cfg);
				return $userPassword  if(ref($userPassword));
				$p_newUser->{'userPassword'} = $userPassword;
			}
			
			my($success,$payload) = $uMgmt->createExtUser($p_newUser);
			
			if($success) {
				my $username = $payload->[0]{'username'};
				unless($NOEMAIL) {
					my %keyval1 = ( 'username' => '(undefined)', 'fullname' => '(undefined)' );
					my %keyval2 = ( 'password' => '(undefined)' );
					
					# Mail configuration parameters
					my $unique = time;
					my $mail1 = GetMailManagementInstance($cfg,$mailTemplate,%keyval1,@attachmentFiles);
					$mail1->setSubject($mail1->getSubject().' (I) ['.$unique.']');
					
					my $passMailTemplate = <<'EOF' ;
The automatically generated password is  [% password %]  (including any punctuation mark it could contain).

You should change this password by a different one as soon as possible.

Kind Regards,
	RD-Connect team
EOF
					my $mail2 = GetMailManagementInstance($cfg,\$passMailTemplate,%keyval2);
					$mail2->setSubject($mail2->getSubject().' (II) ['.$unique.']');
					
					my $fullname = $payload->[0]{'cn'};
					my $email = $payload->[0]{'email'}[0];
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
					print $NOEMAIL "$username\t$userPassword\n";
				}
			} else {
				return {'reason' => 'Error while creating user','trace' => $payload,'code' => 500};
			}
		}
		
		#send_file(\$data, content_type => 'image/jpeg');
		return undef;
	} else {
		return {'reason' => 'Error while fetching mail templates in order to create user','trace' => $payloadMail,'code' => 500};
	}
}

sub ResetUserPassword($$$) {
	my($uMgmt,$userId,$userPassword) = @_;
	
	my $cfg = $uMgmt->getCfg();
	
	unless(defined($userPassword)) {
		$userPassword = GetRandomPassword($cfg);
		return $userPassword  if(ref($userPassword));
	}
	
	my($success,$payload) = $uMgmt->resetUserPassword($userId,$userPassword);
	
	my $retval = undef;
	
	if($success) {
		my %keyval2 = ( 'password' => '(undefined)' );
		
		# Mail configuration parameters
		my $passMailTemplate = <<'EOF' ;
The automatically generated password is  [% password %]  (including any punctuation mark it could contain).

You should change this password by a different one as soon as possible.

Kind Regards,
	RD-Connect team
EOF
		my $unique = time;
		my $mail2 = GetMailManagementInstance($cfg,\$passMailTemplate,%keyval2);
		$mail2->setSubject('RD-Connect password reset for user '.$userId.' ['.$unique.']');
		
		my $fullname = $payload->{'cn'};
		my $email = $payload->{'email'}[0];
		my $to = Email::Address->new($fullname => $email);
		
		$keyval2{'password'} = $userPassword;
		eval {
			$mail2->sendMessage($to,\%keyval2);
		};
		if($@) {
			$retval = {'reason' => 'Error while sending reset password e-mail','trace' => $@,'code' => 500};
		}
	} else {
		$retval = {'reason' => 'Error while resetting user password for user '.$userId,'trace' => $payload,'code' => 500};
	}
	
	#send_file(\$data, content_type => 'image/jpeg');
	return $retval;
}

1;

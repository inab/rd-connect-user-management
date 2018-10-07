#!/usr/bin/perl
# RD-Connect User Management Libraries
# José María Fernández (jose.m.fernandez@bsc.es)

use strict;
use warnings 'all';

use Data::Password::zxcvbn;

use RDConnect::UserManagement;
use RDConnect::MailManagement;
use RDConnect::TemplateManagement;

package RDConnect::MetaUserManagement;

use Scalar::Util qw(blessed);


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
		return bless({'reason' => 'Unable to generate a random password','trace' => $!,'code' => 500},'RDConnect::MetaUserManagement::Error');
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
	my $tMgmt = RDConnect::TemplateManagement->new($uMgmt);
	
	# Before any task
	# Getting the mailTemplate and the attachments for new user creation
	my $mailTemplate;
	my $mailTemplateTitle;
	my @attachmentFiles = ();
	
	my $passMailTemplate;
	my $passMailTemplateTitle;
	my @passAttachmentFiles = ();
	
	unless($NOEMAIL) {
		($mailTemplate,$mailTemplateTitle,@attachmentFiles) = $tMgmt->newUserEmailTemplate();
		
		# Return if error condition
		return $mailTemplate  if(blessed($mailTemplate));
		
		($passMailTemplate,$passMailTemplateTitle,@passAttachmentFiles) = $tMgmt->changedPasswordEmailTemplate();
		
		return $passMailTemplate  if(blessed($passMailTemplate));
	}
	
	$p_newUsers = [ $p_newUsers ]  if(ref($p_newUsers) eq 'HASH');
	
	my @errorStack = ();
	foreach my $p_newUser (@{$p_newUsers}) {
		my $userPassword;
		if(exists($p_newUser->{'userPassword'})) {
			$userPassword = $p_newUser->{'userPassword'};
		} else {
			$userPassword = GetRandomPassword($cfg);
			return $userPassword  if(blessed($userPassword));
			$p_newUser->{'userPassword'} = $userPassword;
		}
		
		my($success,$payload,$p_users) = $uMgmt->createExtUser($p_newUser);
		
		if($success) {
			my $user = $p_users->[0];
			my $username = $payload->[0]{'username'};
			unless($NOEMAIL) {
				my $unique = time;
				
				my %keyval1 = ( 'username' => '(undefined)', 'fullname' => '(undefined)', 'gdprtoken' => '(undefined)', 'unique' => $unique );
				my %keyval2 = ( 'password' => '(undefined)', 'unique' => $unique );
				
				# Mail configuration parameters
				my $mail1 = GetMailManagementInstance($cfg,$mailTemplate,%keyval1,@attachmentFiles);
				$mail1->setSubject($mailTemplateTitle.' (I)');
				
				my $mail2 = GetMailManagementInstance($cfg,$passMailTemplate,%keyval2,@passAttachmentFiles);
				$mail2->setSubject($passMailTemplateTitle.' (II)');
				
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
		return scalar(@errorStack) > 1 ? bless({'reason' => 'Multiple errors','trace' => \@errorStack,'code' => 500},'RDConnect::MetaUserManagement::Error') : bless($errorStack[0],'RDConnect::MetaUserManagement::Error');
	} else {
		return undef;
	}
}

# This method is called from the API and command-line when a password is being changed
sub ResetUserPassword($$$) {
	my($uMgmt,$userId,$userPassword) = @_;
	
	my $cfg = $uMgmt->getCfg();
	my $tMgmt = RDConnect::TemplateManagement->new($uMgmt);
	
	my($mailTemplate,$mailTemplateTitle,@attachmentFiles) = $tMgmt->fetchEmailTemplate(RDConnect::TemplateManagement::GDPRDomain());
	
	# Error condition
	return $mailTemplate  if(blessed($mailTemplate));
	
	if(defined($userPassword)) {
		# Now, let's check the strength of the input password
		my $evPass = Data::Password::zxcvbn::password_strength($userPassword);
		return bless({'reason' => 'Password is too weak','trace' => $evPass,'code' => 400},'RDConnect::MetaUserManagement::Error')  if($evPass->{'score'} < 3);
	} else {
		$userPassword = GetRandomPassword($cfg);
		return $userPassword  if(blessed($userPassword));
	}
	
	my($passMailTemplate,$passMailTemplateTitle,@passAttachmentFiles) = $tMgmt->fetchEmailTemplate(RDConnect::TemplateManagement::ResettedPasswordDomain());
	
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
		my %keyval1 = ( 'username' => '(undefined)', 'fullname' => '(undefined)', 'unique' => $unique );
		my %keyval2 = ( 'password' => '(undefined)', 'unique' => $unique );
		
		# Mail configuration parameters
		my $mail1 = undef;
		
		unless($uMgmt->didUserAcceptGDPR($user)) {
			$mail1 = GetMailManagementInstance($cfg,$mailTemplate,%keyval1,@attachmentFiles);
			$mail1->setSubject($mailTemplateTitle.' (reminder)');
			$keyval1{'gdprtoken'} = $uMgmt->generateGDPRHashFromUser($user);
		}
		
		my $mail2 = GetMailManagementInstance($cfg,$passMailTemplate,%keyval2,@passAttachmentFiles);
		$mail2->setSubject($passMailTemplateTitle);
		
		my $username = $payload->{'username'};
		my $fullname = $payload->{'cn'};
		my $email = $payload->{'email'}[0];
		my $to = Email::Address->new($fullname => $email);
		
		$keyval1{'username'} = $username;
		$keyval1{'fullname'} = $fullname;
		eval {
			if($mail1) {
				$mail1->sendMessage($to,\%keyval1);
			}
			
			$keyval2{'password'} = $userPassword;
			eval {
				$mail2->sendMessage($to,\%keyval2);
			};
			if($@) {
				return bless({'reason' => 'Error while sending password e-mail','trace' => $@,'code' => 500},'RDConnect::MetaUserManagement::Error');
			}
		};
		
		if($@) {
			return bless({'reason' => 'Error while sending user e-mail','trace' => $@,'code' => 500},'RDConnect::MetaUserManagement::Error');
		}
	} else {
		$retval = bless({'reason' => 'Error while resetting user password for user '.$userId,'trace' => $payload,'code' => 500},'RDConnect::MetaUserManagement::Error');
	}
	
	#send_file(\$data, content_type => 'image/jpeg');
	return $retval;
}

1;

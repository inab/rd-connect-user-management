#!/usr/bin/perl
# RD-Connect User Management REST API
# José María Fernández (jose.m.fernandez@bsc.es)

use strict;
use warnings 'all';

package RDConnect::MetaUserManagement;

use RDConnect::UserManagement;
use RDConnect::MailManagement;
use Scalar::Util qw(blessed);

use constant APGSECTION	=>	'apg';


use constant NewUserDomain	=>	'newUserTemplates';
my $DEFAULT_newUserTemplate = <<'EOF' ;
Dear [% fullname %],
        your RD-Connect username is [% username %]. Following the changes in the european GDPR, you must accept
        the code of conduct of RD-Connect. In the meanwhile, your account will be disabled.

        Next link will mark your acceptance of RD-Connect code of conduct.

https://rdconnectcas.rd-connect.eu/RDConnect-UserManagement-API/users/[% username %]/acceptGDPR/[% gdprtoken %]

        Best,
                The RD-Connect team
EOF

use constant ChangedPasswordDomain	=>	'changedPasswordTemplates';
my $DEFAULT_passMailTemplate = <<'EOF' ;
Your new password is  [% password %]  (including any punctuation mark it could contain).

Kind Regards,
	RD-Connect team
EOF

use constant GDPRDomain	=>	'GDPRTemplates';
my $DEFAULT_GDPRTemplate = <<'EOF' ;
<html>
<head>
<title> RD-Connect GPAP: please renew your access in accordance to the EU GDPR </title>
</head>

<body>
<p style="color:red"><b>Do not delete this email! You need the link below to keep accessing the RD-Connect genome-phenome analysis platform!</b></p>


<p>Dear user of the RD-Connect genome-phenome analysis platform (GPAP),</p>

<p>We have updated our policies and procedures to take account of the new General Data Protection Regulation (GDPR, EU 2016/679). As part of this process we have updated the <a href="https://rd-connect.eu/gpap-code-conduct" Alt="RD-Connect Code of Conduct">RD-Connect Code of Conduct</a> and the <a href="https://rd-connect.eu/gpap-adherence" Alt="Adherence Agreement">Adherence Agreement</a> to include more details on how we manage your own user data and the pseudoanonymised genome-phenome data you submit.</p>

<p>So that we can continue providing you with access to the GPAP, we would appreciate it if you could read the updated documents accessible via the links above and confirm your acceptance by clicking your personalised link below.</p>


<p><b>If you are responsible for a user group in the RD-Connect GPAP (usually a Principal Investigator, Group Leader or equivalent)</b>, we need you to confirm you have read, understood and accepted the updated versions of both the Code of Conduct and the Adherence Agreement. You do not need to send us a new signed copy of the Adherence Agreement, but we need you to confirm acceptance online via the link below.</p>


<p><b>If you are a member of a group</b>, you are now also required to confirm you have read, understood and accepted the Code of Conduct. You do this by clicking the link below. Please also remind the person responsible for your user group (usually your Principal Investigator, Group Leader or equivalent) that we also need their confirmation (see above).

<p style="color:red"><b>Please click the link below or copy and paste it into your browser to confirm that you have read, understood and accept the new Code of Conduct (and Adherence Agreement if PI, GL or equirvalent):</b></p>

<p><a href="https://platform.rd-connect.eu/GDPRvalidation/[% username %]/token/[% gdprtoken %]">https://platform.rd-connect.eu/GDPRvalidation/[% username %]/token/[% gdprtoken %]</a></p>

<p>You do not need to log in to the system to provide your confirmation, but unfortunately your access to the system will be blocked until we receive it.</p>
<p>If you need a new confirmation link, a reset of your password, have any questions or experience any problems, please let us know by emailing <a href="mailto:help@rd-connect.eu" Alt="help">help@rd-connect.eu</a>. For urgent issues you can call us on +44 191 241 8621 during office hours.</p>

<p>Thank you very much for your support and understanding,<br><br>The RD-Connect GPAP team</p>
</body>
</html>
EOF

use constant ValidateEmailDomain	=>	'ValidateEmailTemplates';
my $DEFAULT_VALIDATE_EMAIL_TEMPLATE = <<'EOF' ;
Dear RD-Connect user [% username %],
	this e-mail is used to confirm your e-mail address [% email %] is working
and you can read messages from it. You should click on next link:

[% link %]

so the RD-Connect User Management system annotates the e-mail address as functional.

Kind Regards,
	RD-Connect team
EOF

our @MailTemplatesDomains = (
	{
		'apiKey' => 'newUser',
		'desc' => 'New user creation templates',
		'tokens' => [ 'username', 'fullname', 'gdprtoken' ],
		'ldapDomain' => NewUserDomain(),
		'cn' =>	'mailTemplate.html',
		'ldapDesc' => 'New User Mail Template',
		'default' => $DEFAULT_newUserTemplate
	},
	{
		'apiKey' => 'passTemplate',
		'desc' => 'New or resetted password templates',
		'tokens' => [ 'password' ],
		'ldapDomain' => ChangedPasswordDomain(),
		'cn' =>	'changedPassMailTemplate.html',
		'ldapDesc' => 'Changed password mail template',
		'default' => $DEFAULT_passMailTemplate
	},
	{
		'apiKey' => 'GDPRTemplate',
		'desc' => 'GDPR acceptance templates',
		'tokens' => [ 'username', 'fullname', 'gdprtoken' ],
		'ldapDomain' => GDPRDomain(),
		'cn' =>	'GDPRMailTemplate.html',
		'ldapDesc' => 'GDPR acceptance mail template',
		'default' => $DEFAULT_GDPRTemplate
	},
	{
		'apiKey' => 'validEmailTemplate',
		'desc' => 'E-mail validating templates',
		'tokens' => [ 'username', 'fullname' ],
		'ldapDomain' => ValidateEmailDomain(),
		'cn' =>	'ValidateMailTemplate.html',
		'ldapDesc' => 'E-mail validating mail template',
		'default' => $DEFAULT_VALIDATE_EMAIL_TEMPLATE
	}
);

our %MTByApiKey = map { $_->{'apiKey'} => $_ } @MailTemplatesDomains;
my %MTByDomain = map { $_->{'ldapDomain'} => $_ } @MailTemplatesDomains;

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



sub FetchEmailTemplate($$) {
	my($uMgmt,$domainId) = @_;
	
	my($successMail,$payloadMail) = $uMgmt->listJSONDocumentsFromDomain($domainId);
	
	unless($successMail) {
		# Side effect, initialize email template
		# First, get/create the domain
		my($successD,$payloadD) = $uMgmt->getDomain($domainId,1);
		if($successD) {
			$successMail = 1;
			$payloadMail = undef;
		}
	}
	
	if($successMail) {
		# Now, let's fetch
		my $mailTemplate;
		my @attachmentFiles = ();
		
		# Does the domain contain documents?
		if(ref($payloadMail) eq 'ARRAY') {
			foreach my $mailTemplateMetadata (@{$payloadMail}) {
				if(exists($mailTemplateMetadata->{'documentClass'}) && ($mailTemplateMetadata->{'documentClass'} eq 'mailTemplate' || $mailTemplateMetadata->{'documentClass'} eq 'mailAttachment')) {
					# Fetching the document
					my($successT,$payloadT) = $uMgmt->getDocumentFromDomain($domainId,$mailTemplateMetadata->{'cn'});
					
					unless($successT) {
						return bless({'reason' => 'Mail templates not found','trace' => $payloadT,'code' => 404},'RDConnect::MetaUserManagement::Error');
					} elsif(!defined($payloadT)) {
						return bless({'reason' => 'Mail templates do not have document '.$mailTemplateMetadata->{'cn'},'code' => 404},'RDConnect::MetaUserManagement::Error');
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
		} elsif(exists($MTByDomain{$domainId})) {
			my $p_domain = $MTByDomain{$domainId};
			
			my $defaultTemplate = $p_domain->{'default'};
			my $mimeType = 'text/plain';
			
			# Trying to guess the type of file
			eval {
				$mimeType = File::MimeInfo::Magic::mimetype(IO::Scalar->new(\$defaultTemplate));
				$mimeType = 'text/html'  if($mimeType eq 'text/plain' && $defaultTemplate =~ /<(p|div|br|span)>/);
			};
			
			my($successA,$payloadA) = $uMgmt->attachDocumentForDomain(
				$domainId,
				{
					'cn' =>	$p_domain->{'cn'},
					'description' => $p_domain->{'ldapDesc'},
					'documentClass' => 'mailTemplate',
				},
				$defaultTemplate,
				$mimeType
			);
			
			# Last, set the return value
			if($successA) {
				$mailTemplate = {
					'content' => \$defaultTemplate,
					'mime' => $mimeType
				};
			}
		}
		
		unless(defined($mailTemplate)) {
			return bless({'reason' => 'Error while fetching mail templates from domain '.$domainId,'trace' => $payloadMail,'code' => 500},'RDConnect::MetaUserManagement::Error');
		}
		
		return ($mailTemplate,@attachmentFiles);
	} else {
		return bless({'reason' => 'Error while fetching mail templates from domain '.$domainId,'trace' => $payloadMail,'code' => 500},'RDConnect::MetaUserManagement::Error');
	}
}

sub NewUserEmailTemplate($) {
	my($uMgmt) = @_;
	
	return FetchEmailTemplate($uMgmt,NewUserDomain());
}


sub ChangedPasswordEmailTemplate($) {
	my($uMgmt) = @_;
	
	return FetchEmailTemplate($uMgmt,ChangedPasswordDomain());
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
		return $mailTemplate  if(blessed($mailTemplate));
		
		($passMailTemplate,@passAttachmentFiles) = ChangedPasswordEmailTemplate($uMgmt);
		
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
		return scalar(@errorStack) > 1 ? bless({'reason' => 'Multiple errors','trace' => \@errorStack,'code' => 500},'RDConnect::MetaUserManagement::Error') : bless($errorStack[0],'RDConnect::MetaUserManagement::Error');
	} else {
		return undef;
	}
}

sub ResetUserPassword($$$) {
	my($uMgmt,$userId,$userPassword) = @_;
	
	my $cfg = $uMgmt->getCfg();
	
	my($mailTemplate,@attachmentFiles) = FetchEmailTemplate($uMgmt,GDPRDomain());
	
	# Error condition
	return $mailTemplate  if(blessed($mailTemplate));
	
	unless(defined($userPassword)) {
		$userPassword = GetRandomPassword($cfg);
		return $userPassword  if(blessed($userPassword));
	}

	my($passMailTemplate,@passAttachmentFiles) = ChangedPasswordEmailTemplate($uMgmt);
	
	return $passMailTemplate  if(blessed($passMailTemplate));
	
	my($success,$payload) = $uMgmt->getUser($userId);
	
	my $user;
	if($success) {
		$user = $payload;
		($success,$payload) = $uMgmt->resetUserPassword($userId,$userPassword);
	}
	
	my $retval = undef;
	
	if($success) {
		my %keyval1 = ( 'username' => '(undefined)', 'fullname' => '(undefined)' );
		my %keyval2 = ( 'password' => '(undefined)' );
		
		# Mail configuration parameters
		my $unique = time;
		my $mail1 = undef;
		
		unless($uMgmt->didUserAcceptGDPR($user)) {
			$mail1 = GetMailManagementInstance($cfg,$mailTemplate,%keyval1,@attachmentFiles);
			$mail1->setSubject('RD-Connect GDPR acceptance for user '.$userId.' (reminder) ['.$unique.']');
			$keyval1{'gdprtoken'} = $uMgmt->generateGDPRHashFromUser($user);
		}
		
		my $mail2 = GetMailManagementInstance($cfg,$passMailTemplate,%keyval2,@passAttachmentFiles);
		$mail2->setSubject('RD-Connect password reset for user '.$userId.' ['.$unique.']');
		
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

#!/usr/bin/perl
# RD-Connect User Management Libraries
# José María Fernández (jose.m.fernandez@bsc.es)

use strict;
use warnings 'all';

use File::Basename qw();

package RDConnect::TemplateManagement;

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
use constant ResettedPasswordDomain	=>	'resettedPasswordTemplates';
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
		'tokens' => [ 'username', 'fullname', 'gdprtoken', 'unique' ],
		'ldapDomain' => NewUserDomain(),
		'cn' =>	'mailTemplate.html',
		'ldapDesc' => 'New User Mail Template',
		'defaultTitle' => 'RD-Connect platform portal user creation [[% unique %]]',
		'default' => $DEFAULT_newUserTemplate
	},
	{
		'apiKey' => 'passTemplate',
		'desc' => 'New password templates',
		'tokens' => [ 'password', 'unique' ],
		'ldapDomain' => ChangedPasswordDomain(),
		'cn' =>	'changedPassMailTemplate.html',
		'ldapDesc' => 'Changed password mail template',
		'defaultTitle' => 'RD-Connect platform portal user creation [[% unique %]]',
		'default' => $DEFAULT_passMailTemplate
	},
	{
		'apiKey' => 'resetPassTemplate',
		'desc' => 'Resetted password templates',
		'tokens' => [ 'password', 'unique' ],
		'ldapDomain' => ResettedPasswordDomain(),
		'cn' =>	'resettedPassMailTemplate.html',
		'ldapDesc' => 'Resetted password mail template',
		'defaultTitle' => 'RD-Connect platform portal password change [[% unique %]]',
		'default' => $DEFAULT_passMailTemplate
	},
	{
		'apiKey' => 'GDPRTemplate',
		'desc' => 'GDPR acceptance templates',
		'tokens' => [ 'username', 'fullname', 'gdprtoken', 'unique' ],
		'ldapDomain' => GDPRDomain(),
		'cn' =>	'GDPRMailTemplate.html',
		'ldapDesc' => 'GDPR acceptance mail template',
		'defaultTitle' => 'RD-Connect GDPR acceptance for user [% username %] [[% unique %]]',
		'default' => $DEFAULT_GDPRTemplate
	},
	{
		'apiKey' => 'validEmailTemplate',
		'desc' => 'E-mail validating templates',
		'tokens' => [ 'username', 'fullname', 'unique' ],
		'ldapDomain' => ValidateEmailDomain(),
		'cn' =>	'ValidateMailTemplate.html',
		'ldapDesc' => 'E-mail validating mail template',
		'defaultTitle' => 'RD-Connect platform portal e-mail validation [[% unique %]]',
		'default' => $DEFAULT_VALIDATE_EMAIL_TEMPLATE
	}
);

our %MTByApiKey = map { $_->{'apiKey'} => $_ } @MailTemplatesDomains;
my %MTByDomain = map { $_->{'ldapDomain'} => $_ } @MailTemplatesDomains;


our %MailTemplateKeys = (
	'mailTemplate'	=>	undef,
	'mailTemplateTitle'	=>	undef,
	'mailAttachment'	=>	undef,
);

our @TMetaKeys = ('cn','description','documentClass');


# Parameters:
#	uMgmt: An RDConnect::UserManagement instance
sub new($) {
	my $self = shift;
	my $class = ref($self) || $self;
	
	$self = {}  unless(ref($self));
	
	$self->{'_uMgmt'} = shift;
	
	return bless($self,$class);
}

sub getUserManagementInstance() {
	return $_[0]{'_uMgmt'};
}

sub setEmailTemplate($$$@) {
	my $self = shift;
	
	my($domainId,$mailTemplateTitle,$mailTemplateFile,@attachments) = @_;
	
	my $uMgmt = $self->getUserManagementInstance();
	
	my($successMail,$payloadMail) = $uMgmt->listJSONDocumentsFromDomain($domainId);
	
	unless($successMail) {
		# Side effect, initialize email template
		# First, get/create the domain
		my($successD,$payloadD) = $uMgmt->getDomain($domainId,1);
		if($successD) {
			$successMail = 1;
			$payloadMail = [];
		}
	}
	
	if($successMail) {
		my $jsonDomainDocuments = $payloadMail;
		
		my $retval = undef;
		
		# Start checking the files are readable
		foreach my $file ($mailTemplateFile,@attachments) {
			unless(ref($file) || (-f $file && -r $file)) {
				$retval = bless({'reason' => 'Error before storing mail templates for domain '.$domainId,'trace' => "File $file does not exist",'code' => 500},'RDConnect::TemplateManagement::Error');
				last;
			}
		}
		
		unless(defined($retval)) {
			# Identify what it is being replaced/removed
			my $prevMailTemplate = undef;
			my $prevMailTemplateTitle = undef;
			# These ones are going to be removed always!
			my @other = ();
			foreach my $prevEntry (@{$jsonDomainDocuments}) {
				if($prevEntry->{'documentClass'} eq 'mailTemplate') {
					unless(defined($prevMailTemplate)) {
						$prevMailTemplate = $prevEntry;
					} else {
						push(@other,$prevEntry);
					}
				} elsif($prevEntry->{'documentClass'} eq 'mailTemplateTitle') {
					unless(defined($prevMailTemplateTitle)) {
						$prevMailTemplateTitle = $prevEntry;
					} else {
						push(@other,$prevEntry);
					}
				#} elsif($prevEntry->{'documentClass'} eq 'mailAttachment') {
				#	push(@prevAttachments,$prevEntry);
				} else {
					push(@other,$prevEntry);
				}
			}
			
			# The title
			{
				my($successA,$payloadA);
				
				if(defined($prevMailTemplateTitle)) {
					($successA,$payloadA) = $uMgmt->modifyDocumentFromDomain(
						$domainId,
						$prevMailTemplateTitle->{'cn'},
						$mailTemplateTitle
					);
				} else {
					my $mimeType = 'text/plain';
					my %metadata = (
						'cn' =>	'.templateTitle.txt',
						'description' => 'Template title',
						'documentClass' => 'mailTemplateTitle',
					);
					
					($successA,$payloadA) = $uMgmt->attachDocumentForDomain(
						$domainId,
						\%metadata,
						$mailTemplateTitle,
						$mimeType
					);
				}
				
				unless($successA) {
					$retval = bless({'reason' => 'Error while replacing mail template title from domain '.$domainId,'trace' => $payloadA,'code' => 500},'RDConnect::TemplateManagement::Error');
				}
			}
			
			# The body
			unless(defined($retval)) {
				if(open(my $F,'<:raw',$mailTemplateFile)) {
					local $/;
					my $mailTemplate = <$F>;
					close $F;
					
					my($successA,$payloadA);
					
					if(defined($prevMailTemplate)) {
						($successA,$payloadA) = $uMgmt->modifyDocumentFromDomain(
							$domainId,
							$prevMailTemplate->{'cn'},
							$mailTemplate
						);
					} else {
						my $mimeType = 'text/plain';
						# Trying to guess the type of file
						eval {
							$mimeType = File::MimeInfo::Magic::mimetype(IO::Scalar->new(\$mailTemplate));
							$mimeType = 'text/html'  if($mimeType eq 'text/plain' && $mailTemplate =~ /<(p|div|br|span)>/);
						};
						
						my $p_domain;
						if(exists($MTByDomain{$domainId})) {
							$p_domain = $MTByDomain{$domainId};
						} else {
							$p_domain = {
								'cn'	=>	'unknownTemplate.html',
								'ldapDesc'	=>	'(no description)'
							};
						}
						my %metadata = (
							'cn' =>	$p_domain->{'cn'},
							'description' => $p_domain->{'ldapDesc'},
							'documentClass' => 'mailTemplate',
						);
						
						($successA,$payloadA) = $uMgmt->attachDocumentForDomain(
							$domainId,
							\%metadata,
							$mailTemplate,
							$mimeType
						);
					}
					
					unless($successA) {
						$retval = bless({'reason' => 'Error while replacing mail template body in domain '.$domainId,'trace' => $payloadA,'code' => 500},'RDConnect::TemplateManagement::Error');
					}
				} else {
					$retval = bless({'reason' => "Error while reading mail template body in domain $domainId",'trace' => [$!],'code' => 500},'RDConnect::TemplateManagement::Error');
				}
			}
			
			# Remove previous attachments
			unless(defined($retval)) {
				foreach my $doc (@other) {
					my($success,$payload) = $uMgmt->removeDocumentFromDomain($domainId,$doc->{'cn'});
						
					unless($success) {
						$retval = bless({'reason' => "Error while removing attachment $doc->{'cn'} from domain $domainId",'trace' => $payload,'code' => 500},'RDConnect::TemplateManagement::Error');
						last;
					}
				}
			}
			
			# Add the new attachments
			unless(defined($retval)) {
				foreach my $attachment (@attachments) {
					if(open(my $F,'<:raw',$attachment)) {
						local $/;
						my $attachmentContent = <$F>;
						close $F;
							
						my $mimeType = 'application/octet-stream';
						# Trying to guess the type of file
						eval {
							$mimeType = File::MimeInfo::Magic::mimetype(IO::Scalar->new(\$attachmentContent));
							$mimeType = 'text/html'  if($mimeType eq 'text/plain' && $attachmentContent =~ /<(p|div|br|span)>/);
						};
						
						my %metadata = (
							'cn' =>	File::Basename::basename($attachment),
							'description' => 'attachment',
							'documentClass' => 'mailAttachment',
						);
						
						my($successA,$payloadA) = $uMgmt->attachDocumentForDomain(
							$domainId,
							\%metadata,
							$attachmentContent,
							$mimeType
						);
						
						unless($successA) {
							$retval = bless({'reason' => "Error while storing attachment $attachment for domain $domainId",'trace' => $payloadA,'code' => 500},'RDConnect::TemplateManagement::Error');
							last;
						}
					} else {
						$retval = bless({'reason' => "Error while reading attachment $attachment for domain $domainId",'trace' => [$!],'code' => 500},'RDConnect::TemplateManagement::Error');
						last;
					}
				}
			}
			
			$retval = 1  unless(defined($retval));
		}
		
		return $retval;
	} else {
		return bless({'reason' => 'Error while fetching mail templates from domain '.$domainId,'trace' => $payloadMail,'code' => 500},'RDConnect::TemplateManagement::Error');
	}
}

sub fetchEmailTemplate($) {
	my $self = shift;
	
	my($domainId) = @_;
	
	my $uMgmt = $self->getUserManagementInstance();
	
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
		my $mailTemplateTitle;
		my @attachmentFiles = ();
		
		# Does the domain contain documents?
		if(ref($payloadMail) eq 'ARRAY') {
			foreach my $mailTemplateMetadata (@{$payloadMail}) {
				if(exists($mailTemplateMetadata->{'documentClass'}) && exists($MailTemplateKeys{$mailTemplateMetadata->{'documentClass'}})) {
					# Fetching the document
					my($successT,$payloadT) = $uMgmt->getDocumentFromDomain($domainId,$mailTemplateMetadata->{'cn'});
					
					unless($successT) {
						return bless({'reason' => 'Mail templates not found','trace' => $payloadT,'code' => 404},'RDConnect::TemplateManagement::Error');
					} elsif(!defined($payloadT)) {
						return bless({'reason' => 'Mail templates do not have document '.$mailTemplateMetadata->{'cn'},'code' => 404},'RDConnect::TemplateManagement::Error');
					}
					
					# Here the payload is the document
					my $data = $payloadT->get_value('content');
					my $mime = $payloadT->get_value('mimeType');
					my $preparedMime = {
						'cn' => $mailTemplateMetadata->{'cn'},
						'content' => \$data,
						'mime' => $mime
					};
					if($mailTemplateMetadata->{'documentClass'} eq 'mailTemplate') {
						$mailTemplate = $preparedMime;
					} elsif($mailTemplateMetadata->{'documentClass'} eq 'mailTemplateTitle') {
						# The title is always inline!!!!
						$mailTemplateTitle = $data;
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
			
			my %metadata = (
				'cn' =>	$p_domain->{'cn'},
				'description' => $p_domain->{'ldapDesc'},
				'documentClass' => 'mailTemplate',
			);
			
			my($successA,$payloadA) = $uMgmt->attachDocumentForDomain(
				$domainId,
				\%metadata,
				$defaultTemplate,
				$mimeType
			);
			
			# Last, set the return value
			if($successA) {
				$mailTemplate = {
					'cn' => $metadata{'cn'},
					'content' => \$defaultTemplate,
					'mime' => $mimeType
				};
			}
		}
		
		if(defined($mailTemplate)) {
			# Special case: no title
			unless(defined($mailTemplateTitle)) {
				my $p_domain = $MTByDomain{$domainId};
				
				my $defaultTemplateTitle = $p_domain->{'defaultTitle'};
				my $mimeType = 'text/plain';
				
				my %metadata = (
					'cn' =>	'.templateTitle.txt',
					'description' => 'Template title',
					'documentClass' => 'mailTemplateTitle',
				);
				my($successA,$payloadA) = $uMgmt->attachDocumentForDomain(
					$domainId,
					\%metadata,
					$defaultTemplateTitle,
					$mimeType
				);
				
				# Last, set the return value
				if($successA) {
					# The title always goes inline
					$mailTemplateTitle = $defaultTemplateTitle;
				} else {
					return bless({'reason' => 'Error while fetching mail templates from domain '.$domainId,'trace' => $payloadA,'code' => 500},'RDConnect::TemplateManagement::Error');
				}
			}
		} else {
			return bless({'reason' => 'Error while fetching mail templates from domain '.$domainId,'trace' => $payloadMail,'code' => 500},'RDConnect::TemplateManagement::Error');
		}
		
		return ($mailTemplate,$mailTemplateTitle,@attachmentFiles);
	} else {
		return bless({'reason' => 'Error while fetching mail templates from domain '.$domainId,'trace' => $payloadMail,'code' => 500},'RDConnect::TemplateManagement::Error');
	}
}

sub newUserEmailTemplate($) {
	my $self = shift;
	
	return $self->fetchEmailTemplate(NewUserDomain());
}


sub changedPasswordEmailTemplate($) {
	my $self = shift;
	
	return $self->fetchEmailTemplate(ChangedPasswordDomain());
}

1;

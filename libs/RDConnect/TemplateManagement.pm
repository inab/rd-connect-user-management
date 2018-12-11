#!/usr/bin/perl
# RD-Connect User Management Libraries
# José María Fernández (jose.m.fernandez@bsc.es)

use strict;
use warnings 'all';

use File::Basename qw();

package RDConnect::TemplateManagement;


# Global variable for the templates
our @MailTemplatesDomains;
our %MTByApiKey;
my %MTByDomain;
my %MTByRequestType;

# Management methods
BEGIN {
	sub AddMailTemplatesDomains(@) {
		push(@MailTemplatesDomains,@_);
		
		%MTByApiKey = map { $_->{'apiKey'} => $_ } @MailTemplatesDomains;
		%MTByDomain = map { $_->{'ldapDomain'} => $_ } @MailTemplatesDomains;
		%MTByRequestType = map { $_->{'requestType'} => $_ } grep { exists($_->{'requestType'}) } @MailTemplatesDomains;
	}
}


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
	return $_[0]->{'_uMgmt'};
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

sub fetchEmailTemplateByRequestType($) {
	my $self = shift;
	
	my($requestType) = @_;
	
	# Are there templates declared for this request type?
	if(exists($MTByRequestType{$requestType})) {
		my $domainId = $MTByRequestType{$requestType}->{'ldapDomain'};
		
		return $self->fetchEmailTemplate($domainId);
	} else {
		return bless({'reason' => 'Error while fetching mail templates for request type '.$requestType,'code' => 500},'RDConnect::TemplateManagement::Error');
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


# This method extracts the available e-mail addressess to notify a user
# If all the e-mail addressess are under test, then use those
sub getEmailAddressesFromJSONUser(\%) {
	my $self = shift;
	
	my($jsonUser) = @_;
	
	my $p_addresses = [];
	
	if(exists($jsonUser->{'email'}) && ref($jsonUser->{'email'}) eq 'ARRAY' && scalar(@{$jsonUser->{'email'}}) > 0) {
		$p_addresses = $jsonUser->{'email'};
	} elsif(exists($jsonUser->{'registeredEmails'}) && ref($jsonUser->{'registeredEmails'}) eq 'ARRAY' && scalar(@{$jsonUser->{'registeredEmails'}}) > 0) {
		$p_addresses = [ map { $_->{'email'} } @{$jsonUser->{'registeredEmails'}} ];
	}
	
	return $p_addresses;
}

sub mailTemplateStructureByApiKey($) {
	my $self = shift;
	
	my($apiKey) = @_;
	
	return exists($MTByApiKey{$apiKey}) ? $MTByApiKey{$apiKey} : undef;
}

sub mailTemplateStructureByDomain($) {
	my $self = shift;
	
	my($domainId) = @_;
	
	return exists($MTByDomain{$domainId}) ? $MTByDomain{$domainId} : undef;
}

sub mailTemplateStructureByRequestType($) {
	my $self = shift;
	
	my($requestType) = @_;
	
	return exists($MTByRequestType{$requestType}) ? $MTByRequestType{$requestType} : undef;
}

sub getMailTemplatesDomains() {
	my $self = shift;
	
	return \@MailTemplatesDomains;
}

1;

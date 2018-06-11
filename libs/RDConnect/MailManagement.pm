#!/usr/bin/perl -w

use strict;
package RDConnect::MailManagement;

use Carp;
use Email::Address;
use Email::MIME;
use Email::Sender::Simple qw(sendmail);
use Email::Sender::Transport::SMTPS qw();
use File::Basename qw();
use File::MimeInfo::Magic qw();
use IO::Scalar;

use constant MAILSECTION	=>	'mail';

my %DEFAULT_keyval = ( 'username' => '(undefined)', 'fullname' => '(undefined)' );


use File::Spec;

use constant MAIL_VALIDATION_SCHEMA_FILE	=>	'mailValidation.json';
use constant FULL_MAIL_VALIDATION_SCHEMA_FILE	=>	File::Spec->catfile(File::Basename::dirname(__FILE__),MAIL_VALIDATION_SCHEMA_FILE);

# Parameters:
#	cfg: A Config::IniFiles instance
#	mailTemplate: a file with the mail template, or a reference to a string containing it
#	p_keyval: a reference to a hash containing the default values for substitution keys in the template
#	p_attachmentFiles: a reference to an array containing paths to the attachments to be sent
sub new($$\%;\@) {
	my $self = shift;
	my $class = ref($self) || $self;
	
	$self = {}  unless(ref($self));
	
	my $cfg = shift;
	my $configFile = $cfg->GetFileName;
	
	my $mailTemplateParam = shift;
	my %defaultKeyval = ();
	my $p_keyval = shift;
	@defaultKeyval{keys(%{$p_keyval})} = values(%{$p_keyval})  if(ref($p_keyval) eq 'HASH');
	
	my $p_attachmentFiles = shift;
	my @attachmentFiles = (ref($p_attachmentFiles) eq 'ARRAY') ? @{$p_attachmentFiles} : ();
	
	# Mail configuration parameters
	my @mailParams = ();
	foreach my $mailParam ('host','ssl','port','sasl_username','sasl_password') {
		push(@mailParams,$mailParam,$cfg->val(MAILSECTION,$mailParam))  if($cfg->exists(MAILSECTION,$mailParam));
	}
	my $transport = Email::Sender::Transport::SMTPS->new(@mailParams);
	
	my($from) = Email::Address->parse($cfg->val(MAILSECTION,'from'));
	
	Carp::croak("subject field must be defined in order to send e-mails")  unless($cfg->exists(MAILSECTION,'subject'));
	my $subject = $cfg->val(MAILSECTION,'subject');
	
	# Read the mail body
	my $templateMailBodyMime;
	my $templateMailBody;
	
	my $mailTemplate;
	if(ref($mailTemplateParam) eq 'HASH') {
		$mailTemplate = $mailTemplateParam->{'content'};
		$templateMailBodyMime = $mailTemplateParam->{'mime'};
	} else {
		$mailTemplate = $mailTemplateParam;
	}
	
	# Is it a file or a reference to an scalar?
	my $mailTemplateH = (ref($mailTemplate) eq 'SCALAR') ? IO::Scalar->new($mailTemplate) : $mailTemplate;
	unless(defined($templateMailBodyMime)) {
		eval {
			$templateMailBodyMime = File::MimeInfo::Magic::mimetype($mailTemplateH);
			if($templateMailBodyMime eq 'text/plain' && ref($mailTemplate) eq 'SCALAR' && $$mailTemplate =~ /<(p|div|br|span)>/) {
				$templateMailBodyMime = 'text/html';
			}
		};
		Carp::croak("ERROR: Unable to pre-process mail template $mailTemplate . Reason: ".($@ ? $@ : '(undefined mail body mime)'))  if($@ || !defined($templateMailBodyMime));
	}
		
	if(ref($mailTemplate) eq 'SCALAR') {
		$templateMailBody = ${$mailTemplate};
	} else {
		if(open(my $TT,'<:encoding(UTF-8)',$mailTemplate)) {
			local $/;
			$templateMailBody = <$TT>;
			
			close($TT);
		} else {
			Carp::croak("Unable to read template body");
		}
	}
	
	# These are the recognized replacements
	my %replacements = map { $_ => undef } $templateMailBody =~ /\[% ([a-zA-Z0-9._-]+) %\]/g;
	foreach my $var (keys(%replacements)) {
		Carp::carp("WARNING: annotation $var in template does not exist")  unless(exists($defaultKeyval{$var}));
	}
	
	# Identify the attachments
	my @attachments = ();
	foreach my $attachmentFileComponent (@attachmentFiles) {
		my $attachmentFile;
		my $mime;
		if(ref($attachmentFileComponent) eq 'HASH') {
			$attachmentFile = $attachmentFileComponent->{'content'};
			$mime = $attachmentFileComponent->{'mime'};
		} else {
			my $attachmentFile = (ref($attachmentFileComponent) eq 'SCALAR') ? IO::Scalar->new($attachmentFileComponent) : $attachmentFileComponent;
			eval {
				$mime = File::MimeInfo::Magic::mimetype($attachmentFile);
				if($mime eq 'text/plain' && ref($attachmentFileComponent) eq 'SCALAR' && $$attachmentFileComponent =~ /<(p|div|br|span)>/) {
					$mime = 'text/html';
				}
			};
		}
		
		Carp::croak("ERROR: Unable to pre-process attachment $attachmentFile")  if($@ || !defined($mime));
		
		if(open(my $AT,'<:raw',$attachmentFile)) {
			local $/;
			push(@attachments,Email::MIME->create(
				attributes => {
					filename => File::Basename::basename($attachmentFile),
					content_type => $mime,
					disposition => "attachment",
					encoding => "base64",
					# name => ,
				},
				body => <$AT>
			));
			
			close($AT);
		} else {
			Carp::croak("ERROR: Unable to read attachment $attachmentFile");
		}
	}
	
	$self->{'transport'} = $transport;
	$self->{'from'} = $from;
	$self->{'subject'} = $subject;
	$self->{'defaultKeyval'} = \%defaultKeyval;
	$self->{'templateMailBody'} = $templateMailBody;
	$self->{'templateMailBodyMime'} = $templateMailBodyMime;
	$self->{'replacements'} = \%replacements;
	$self->{'attachments'} = \@attachments  if(scalar(@attachments)>0);
	
	return bless($self,$class);
}

sub getSubject() {
	my $self = shift;
	
	return $self->{'subject'};
}

sub setSubject($) {
	my $self = shift;
	
	$self->{'subject'} = shift;
}

# Parameters:
#	to: A Email::Address instance, or an array of instances
#	p_keyval: a reference to a hash
sub sendMessage($\%) {
	my $self = shift;
	
	my($to,$p_keyval)=@_;
	
	# Preparing and sending the e-mails
	my $mailBody = $self->{'templateMailBody'};
	my $subject = $self->{'subject'};
	
	foreach my $var (keys(%{$self->{'replacements'}})) {
		my $val = exists($p_keyval->{$var}) ? $p_keyval->{$var} : (exists($self->{'defaultKeyval'}{$var}) ? $self->{'defaultKeyval'}{$var} : '(FIXME!)');
		
		$mailBody =~ s/\Q[% $var %]\E/$val/g;
		$subject =~ s/\Q[% $var %]\E/$val/g;
	}
	
	my $mailPart = Email::MIME->create(
		attributes => {
			encoding => 'quoted-printable',
			content_type => $self->{'templateMailBodyMime'},
			charset  => 'UTF-8',
		},
		body_str => $mailBody
	);
	
	my $message;
	my $p_header_str = [
		From	=>	$self->{'from'},
		To	=>	$to,
		Subject	=>	$subject
	];
	#if(exists($self->{'attachments'})) {
		my @parts = ( $mailPart );
		push(@parts,@{$self->{'attachments'}})  if(exists($self->{'attachments'}));
		$message = Email::MIME->create(
			header_str => $p_header_str,
			attributes => {
				content_type => 'multipart/mixed'
			},
			parts => \@parts
		);
	#} else {
	#	$message = $mailPart;
	#	my $headerLength = scalar(@{$p_header_str});
	#	for(my $i=0;$i<$headerLength;$i+=2) {
	#		$message->header_str_set($p_header_str->[$i]	=>	$p_header_str->[$i+1]);
	#	}
	#}
	eval {
		sendmail($message, { from => $self->{'from'}->address(), transport => $self->{'transport'} });
	};
	
	if($@) {
		Carp::croak("Error while sending e-mail: ",$@);
	}
}

1;

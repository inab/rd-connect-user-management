#!/usr/bin/perl -w
# RD-Connect User Management Libraries
# José María Fernández (jose.m.fernandez@bsc.es)

use strict;
package RDConnect::MailManagement;

use Carp;
use Email::Address;
use Email::MIME;
use Email::Sender::Simple qw(sendmail);
use Email::Sender::Transport::SMTP qw();
use File::Basename qw();
use File::MimeInfo::Magic qw();
use IO::Scalar;

use constant MAILSECTION	=>	'mail';

my %DEFAULT_keyval = ( 'username' => '(undefined)', 'fullname' => '(undefined)' );


use File::Spec;

use constant SCHEMAS_REL_DIR	=>	'schemas';

use constant MAIL_VALIDATION_SCHEMA_FILE	=>	'mailValidation.json';
use constant FULL_MAIL_VALIDATION_SCHEMA_FILE	=>	File::Spec->catfile(File::Basename::dirname(__FILE__),SCHEMAS_REL_DIR,MAIL_VALIDATION_SCHEMA_FILE);

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
	foreach my $mailParam ('host','port','ssl','helo','sasl_username','sasl_password','debug') {
		push(@mailParams,$mailParam,$cfg->val(MAILSECTION,$mailParam))  if($cfg->exists(MAILSECTION,$mailParam));
	}
	
	if($cfg->exists(MAILSECTION,'ssl_options')) {
		my $keyvalstr = $cfg->val(MAILSECTION,'ssl_options');
		my @keyval = split(/;/,$keyvalstr);
		my %keydata = ();
		foreach my $keyv (@keyval) {
			my($key,$val) = split(/=/,$keyv);
			$keydata{$key} = $val;
		}
		push(@mailParams,'ssl_options',\%keydata);
	}
	
	my $transport = Email::Sender::Transport::SMTP->new(@mailParams);
	
	my($from) = Email::Address->parse($cfg->val(MAILSECTION,'from'));
	
	my $replyTo = undef;
	if($cfg->exists(MAILSECTION,'reply-to')) {
		($replyTo) = Email::Address->parse($cfg->val(MAILSECTION,'reply-to'));
	}
	
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
		$templateMailBodyMime = 'text/plain';
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
	
	# Identify the attachments
	my @attachments = ();
	foreach my $attachmentFileComponent (@attachmentFiles) {
		my $attachmentFile;
		my $attachmentFilename;
		my $mime;
		if(ref($attachmentFileComponent) eq 'HASH') {
			$attachmentFile = $attachmentFileComponent->{'content'};
			$attachmentFilename = $attachmentFileComponent->{'cn'};
			$mime = $attachmentFileComponent->{'mime'};
		} else {
			$attachmentFile = $attachmentFileComponent;
			$attachmentFilename = $attachmentFileComponent;
			my $attachmentDetFile = (ref($attachmentFile) eq 'SCALAR') ? IO::Scalar->new($attachmentFile) : $attachmentFile;
			eval {
				$mime = File::MimeInfo::Magic::mimetype($attachmentDetFile);
				if($mime eq 'text/plain' && ref($attachmentFile) eq 'SCALAR' && $$attachmentFile =~ /<(p|div|br|span)>/) {
					$mime = 'text/html';
				}
			};
		}
		
		Carp::croak("ERROR: Unable to pre-process attachment $attachmentFile")  if($@ || !defined($mime));
		
		my $attachmentContent = undef;
		if(ref($attachmentFile) eq 'SCALAR') {
			$attachmentContent = $$attachmentFile;
		} elsif(open(my $AT,'<:raw',$attachmentFile)) {
			local $/;
			$attachmentContent = <$AT>;
			
			close($AT);
		}
		
		if(defined($attachmentContent)) {
			push(@attachments,Email::MIME->create(
				attributes => {
					filename => File::Basename::basename($attachmentFilename),
					content_type => $mime,
					disposition => "attachment",
					encoding => "base64",
					# name => ,
				},
				body => $attachmentContent
			));
		} else {
			Carp::croak("ERROR: Unable to read attachment $attachmentFile");
		}
	}
	
	$self->{'transport'} = $transport;
	$self->{'from'} = $from;
	$self->{'reply-to'} = $replyTo  if(defined($replyTo));
	$self->{'subject'} = $subject;
	$self->{'defaultKeyval'} = \%defaultKeyval;
	$self->{'templateMailBody'} = $templateMailBody;
	$self->{'templateMailBodyMime'} = $templateMailBodyMime;
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
	
	# These are the recognized replacements
	my %replacements = map { $_ => undef } ($mailBody =~ /\[% ([a-zA-Z0-9._-]+) %\]/g, $subject =~ /\[% ([a-zA-Z0-9._-]+) %\]/g);
	
	foreach my $var (keys(%replacements)) {
		Carp::carp("WARNING: annotation $var in template does not exist")  unless(exists($self->{'defaultKeyval'}{$var}));
		my $val = exists($p_keyval->{$var}) ? $p_keyval->{$var} : (exists($self->{'defaultKeyval'}{$var}) ? $self->{'defaultKeyval'}{$var} : '(FIXME!)');
		
		my $pat = quotemeta("[% $var %]");
		
		$mailBody =~ s/$pat/$val/g;
		$subject =~ s/$pat/$val/g;
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
	if(exists($self->{'reply-to'})) {
		push(@{$p_header_str},'Reply-To',$self->{'reply-to'});
	}
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

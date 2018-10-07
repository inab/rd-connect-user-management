#!/usr/bin/perl
# RD-Connect User Management Libraries
# José María Fernández (jose.m.fernandez@bsc.es)

use strict;
use warnings 'all';

package RDConnect::RequestManagement;

# Parameters:
#	tMgmt: An RDConnect::TemplateManagement instance
sub new($$) {
	my $self = shift;
	my $class = ref($self) || $self;
	
	$self = {}  unless(ref($self));
	
	$self->{_tMgmt} = shift;
	$self->{_uMgmt} = $self->{_tMgmt}->getUserManagementInstance();
	
	return bless($self,$class);
}


sub getUserManagementInstance() {
	return $_[0]{'_uMgmt'};
}

sub getTemplateManagementInstance() {
	return $_[0]{'_tMgmt'};
}

sub removeRequest($) {
	return $_[0]->getUserManagementInstance()->removeRequest($_[1]);
}

sub getRequestPayload($) {
	return $_[0]->getUserManagementInstance()->getRequestPayload($_[1]);
}

use constant {
	REQ_PASSWORD_RESET	=>	"passwordReset",
	REQ_EMAIL_CONFIRM	=>	"emailConfirmation",
	REQ_ACCEPT_GDPR	=>	"acceptGDPR",
};

my %RequestClass = (
	REQ_PASSWORD_RESET()	=> {
		'method'	=>	'doPasswordReset',
		'view'	=>	'',
	},
	REQ_EMAIL_CONFIRM()	=> {
		'method'	=>	'',
		'view'	=>	'',
	},
	REQ_ACCEPT_GDPR()	=> {
		'method'	=>	'',
		'view'	=>	'',
	},
);

sub doPasswordReset($) {
	my $self = shift;
	
	my($answerPayload) = @_;
	
	return
}

sub resolveRequest($$) {
	my $self = shift;
	
	my($requestType,$answerPayload) = @_;
	
	my $answerResolution = undef;
	
	if(exists($RequestClass{$requestType})) {
		my $methodName = $RequestClass{$requestType}{'method'};
		return $self->$methodName($answerPayload);
	}
	
	return undef;
}

sub getRequestView($) {
	my $self = shift;
	
	my($requestType) = @_;
	
	my $view = undef;
	
	if(exists($RequestClass{$requestType})) {
		# TODO
	}
	
	return $view;
}

1;

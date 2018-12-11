#!/usr/bin/perl
# RD-Connect User Management Libraries
# José María Fernández (jose.m.fernandez@bsc.es)

use strict;
use warnings 'all';

use RDConnect::TemplateManagement;

package RDConnect::RequestManagement;


use constant {
	REQ_INIT_PASSWORD_RESET	=>	"initPasswordReset",
	REQ_PASSWORD_RESET	=>	"passwordReset",
	REQ_EMAIL_CONFIRM	=>	"emailConfirmation",
	REQ_ACCEPT_GDPR	=>	"acceptGDPR",
};

# Registering the templates only once
BEGIN {

	my $DEFAULT_PassResetReqTemplate = <<'EOF' ;
Dear [% fullname %],
        your RD-Connect username is [% username %]. You or an RD-Connect administrator have recently requested to change your password. If it is so, please follow next link:

[% requestlink %]

Otherwise, follow next link in order to remove this request

[% desistlink %]

        These links will be valid until [% expiration %].

        Best,
                The RD-Connect team
EOF

	use constant GDPRTextDomain	=>	'GDPRTextBody';
	my $DEFAULT_GDPRText = <<'EOF' ;
<div>
<p>Dear user of the RD-Connect genome-phenome analysis platform (GPAP),</p>

<p>We have updated our policies and procedures to take account of the new General Data Protection Regulation (GDPR, EU 2016/679). As part of this process we have updated the <a href="https://rd-connect.eu/gpap-code-conduct" Alt="RD-Connect Code of Conduct">RD-Connect Code of Conduct</a> and the <a href="https://rd-connect.eu/gpap-adherence" Alt="Adherence Agreement">Adherence Agreement</a> to include more details on how we manage your own user data and the pseudoanonymised genome-phenome data you submit.</p>

<p>So that we can continue providing you with access to the GPAP, we would appreciate it if you could read the updated documents accessible via the links above and confirm your acceptance by clicking your personalised link below.</p>


<p><b>If you are responsible for a user group in the RD-Connect GPAP (usually a Principal Investigator, Group Leader or equivalent)</b>, we need you to confirm you have read, understood and accepted the updated versions of both the Code of Conduct and the Adherence Agreement. You do not need to send us a new signed copy of the Adherence Agreement, but we need you to confirm acceptance online via the link below.</p>


<p><b>If you are a member of a group</b>, you are now also required to confirm you have read, understood and accepted the Code of Conduct. You do this by clicking the link below. Please also remind the person responsible for your user group (usually your Principal Investigator, Group Leader or equivalent) that we also need their confirmation (see above).
</div>
EOF

	use constant GDPRDomain	=>	'GDPRTemplates';
	my $DEFAULT_GDPRTemplate = <<'EOF' ;
<html>
<head>
<title> RD-Connect GPAP: please renew your access in accordance to the EU GDPR </title>
</head>

<body>
<p style="color:red"><b>Do not delete this email! You need the link below to keep accessing the RD-Connect genome-phenome analysis platform!</b></p>

[% gdprtext %]

<p style="color:red"><b>Please click the link below or copy and paste it into your browser to confirm that you have read, understood and accept the new Code of Conduct (and Adherence Agreement if PI, GL or equivalent):</b></p>

<p><a href="[% requestlink %]">[% requestlink %]</a></p>

<p>You do not need to log in to the system to provide your confirmation, but unfortunately your access to the system will be blocked until we receive it. The link will be valid until [% expiration %].</p>
<p>If you need a new confirmation link, a reset of your password, have any questions or experience any problems, please let us know by emailing <a href="mailto:help@rd-connect.eu" Alt="help">help@rd-connect.eu</a>. For urgent issues you can call us on +44 191 241 8621 during office hours.</p>

<p>Thank you very much for your support and understanding,<br><br>The RD-Connect GPAP team</p>
</body>
</html>
EOF

	use constant ValidateEmailDomain	=>	'ValidateEmailTemplates';
	my $DEFAULT_VALIDATE_EMAIL_TEMPLATE = <<'EOF' ;
Dear RD-Connect user [% username %],
	this e-mail is used to confirm your e-mail address [% emailtoConfirm %] is working
and you can read messages from it. You should click on next link:

[% requestlink %]

so the RD-Connect User Management system annotates the e-mail address as functional.

If you are unrelated to RD-Connect, please follow next link

[% desistlink %]

These links will be valid until [% expiration %].


Kind Regards,
	RD-Connect team
EOF

	RDConnect::TemplateManagement::AddMailTemplatesDomains(
		{
			'apiKey' => 'passResetReq',
			'desc' => 'Password reset request templates',
			'tokens' => [ 'username', 'fullname', 'requestlink', 'desistlink', 'expiration', 'unique' ],
			'ldapDomain' => 'PasswordResetRequest',
			'requestType' => REQ_PASSWORD_RESET(),
			'cn' =>	'PassResetReqTemplate.html',
			'ldapDesc' => 'Request password reset template',
			'defaultTitle' => 'RD-Connect platform portal password change [[% unique %]]',
			'default' => $DEFAULT_PassResetReqTemplate
		},
		{
			'apiKey' => 'validEmailTemplate',
			'desc' => 'E-mail validating templates',
			'tokens' => [ 'username', 'fullname', 'emailToConfirm', 'requestlink', 'desistlink', 'expiration', 'unique' ],
			'ldapDomain' => ValidateEmailDomain(),
			'requestType' => REQ_EMAIL_CONFIRM(),
			'cn' =>	'ValidateMailTemplate.html',
			'ldapDesc' => 'E-mail validating mail template',
			'defaultTitle' => 'RD-Connect platform portal e-mail validation [[% unique %]]',
			'default' => $DEFAULT_VALIDATE_EMAIL_TEMPLATE
		},
		{
			'apiKey' => 'GDPRTemplate',
			'desc' => 'GDPR acceptance templates',
			'tokens' => [ 'username', 'fullname', 'requestlink', 'desistlink', 'expiration', 'gdprtext', 'unique' ],
			'deps' => {
				'gdprtext' => GDPRTextDomain()
			},
			'ldapDomain' => GDPRDomain(),
			'requestType' => REQ_ACCEPT_GDPR(),
			'cn' =>	'GDPRMailTemplate.html',
			'ldapDesc' => 'GDPR acceptance mail template',
			'defaultTitle' => 'RD-Connect GDPR acceptance for user [% username %] [[% unique %]]',
			'default' => $DEFAULT_GDPRTemplate
		},
		{
			'apiKey' => 'GDPRText',
			'desc' => 'GDPR text body',
			'tokens' => [],
			'ldapDomain' => GDPRTextDomain(),
			'requestType' => REQ_ACCEPT_GDPR().'fake',
			'cn' =>	'GDPRtextBody.html',
			'ldapDesc' => 'GDPR text body',
			'defaultTitle' => 'RD-Connect GDPR text body',
			'default' => $DEFAULT_GDPRText
		},
	);
}


use constant	REQUEST_SECTION	=>	'requests';

# Parameters:
#	tMgmt: An RDConnect::TemplateManagement instance
sub new($) {
	my $self = shift;
	my $class = ref($self) || $self;
	
	$self = {}  unless(ref($self));
	
	$self->{'_tMgmt'} = shift;
	$self->{'_uMgmt'} = $self->{'_tMgmt'}->getUserManagementInstance();
	
	#  Getting the public base URI
	my $cfg = $self->{'_uMgmt'}->getCfg();
	my $publicBaseURI = $cfg->val(REQUEST_SECTION,'public_base_uri');
	Carp::croak("public_base_uri was not defined")  unless(defined($publicBaseURI));
	$self->{'publicBaseURI'} = $publicBaseURI;
	
	# This will be initialized later
	$self->{'_mMgmt'} = undef;
	
	return bless($self,$class);
}


sub getUserManagementInstance() {
	return $_[0]->{'_uMgmt'};
}

sub getTemplateManagementInstance() {
	return $_[0]->{'_tMgmt'};
}

sub getMetaUserManagementInstance() {
	return $_[0]->{'_mMgmt'};
}

sub setMetaUserManagementInstance() {
	my $self = shift;
	
	$self->{'_mMgmt'} = shift;
}


sub removeRequest($) {
	return $_[0]->getUserManagementInstance()->removeRequest($_[1]);
}

use constant {
	STATIC_PASSWORD_RESET_REQ_ID	=>	'password-reset',
};

my %StaticRequests = (
	STATIC_PASSWORD_RESET_REQ_ID()	=> {
		'requestType'	=>	REQ_INIT_PASSWORD_RESET(),
		'publicPayload'	=>	{},
		'desistCode'	=>	'never'
	},
);



sub getRequestPayload($) {
	my $self = shift;
	
	my($requestId) = @_;
	
	# This check is here for static methods
	if(exists($StaticRequests{$requestId})) {
		my $p_staticPayload = $StaticRequests{$requestId};
		
		return (1,$p_staticPayload);
	}
	
	# Defer to the LDAP search
	return $self->getUserManagementInstance()->getRequestPayload($requestId);
}

my %RequestClass = (
	REQ_INIT_PASSWORD_RESET()	=> {
		'method'	=>	'doInitPasswordReset',
		'view'	=>	'requestPasswordResetView',
		'desistView'	=>	'desistView',
	},
	REQ_PASSWORD_RESET()	=> {
		'method'	=>	'doPasswordReset',
		'view'	=>	'passwordResetView',
		'desistView'	=>	'desistView',
	},
	REQ_EMAIL_CONFIRM()	=> {
		'method'	=>	'doConfirmEMail',
		'view'	=>	'confirmEmailView',
		'desistView'	=>	'desistView',
	},
	REQ_ACCEPT_GDPR()	=> {
		'method'	=>	'doAcceptGDPR',
		'view'	=>	'acceptGDPRView',
		'desistView'	=>	'desistView',
	},
);

# The different default timeouts
use constant DEFAULT__PASSWORD_RESET_TIMEOUT	=>	1*24*60*60;
use constant DEFAULT__ACCEPT_GDPR_TIMEOUT	=>	30*24*60*60;

# With this, any user is requesting to reset her/his password
sub doInitPasswordReset(\%\%) {
	my $self = shift;
	
	my($requestPayload,$answerPayload) = @_;
	
	# Is the username or e-mail provided?
	my $usernameOrEmail = $answerPayload->{'usernameOrEmail'};
	my $success = defined($usernameOrEmail);
	if($success) {
		my $mMgmt = $self->getMetaUserManagementInstance();
		($success,undef,undef) = $mMgmt->createPasswordResetRequest($usernameOrEmail);
	}
	
	return $success;
}

sub doPasswordReset(\%\%) {
	my $self = shift;
	
	my($requestPayload,$answerPayload) = @_;
	
	my $newPassword = $answerPayload->{'password'};
	my $success = defined($newPassword);
	if($success) {
		my $mMgmt = $self->getMetaUserManagementInstance();
		
		$mMgmt->resetUserPassword($requestPayload->{'target'}{'id'},$newPassword);
	}
	
	return $success;
}

sub doConfirmEMail(\%\%) {
	my $self = shift;
	
	my($requestPayload,$answerPayload) = @_;
	
	my $success = $answerPayload->{'confirmEmail'};
	if(defined($success) && $answerPayload->{'confirmEmail'} eq $requestPayload->{'publicPayload'}{'emailToConfirm'}) {
		my $uMgmt = $self->getUserManagementInstance();
		
		$uMgmt->confirmUserEMail($requestPayload->{'target'}{'id'},$requestPayload->{'publicPayload'}{'emailToConfirm'});
	}
	
	return $success;
}

sub doAcceptGDPR(\%\%) {
	my $self = shift;
	
	my($requestPayload,$answerPayload) = @_;
	
	my $acceptedGDPR = $answerPayload->{'GDPRtoken'};
	my $success = defined($acceptedGDPR);
	if($success && length($acceptedGDPR) > 0) {
		my $uMgmt = $self->getUserManagementInstance();
		my $username = $requestPayload->{'target'}{'id'};
		
		# Does the user exist?
		my($success,$user) = $uMgmt->getUser($username);
		if($success) {
			# Accept token
			$success = $uMgmt->acceptGDPRHashFromUser($user,$acceptedGDPR);
			
			if($success) {
				# Send notifications of e-mail re-validation
				my $mMgmt = $self->getMetaUserManagementInstance();
				
				$mMgmt->sendUsernameEMailRequests($user);
			}
		}
	}
	
	return $success;
}


sub resolveRequest($$) {
	my $self = shift;
	
	my($requestPayload,$answerPayload) = @_;
	
	my $requestType = $requestPayload->{'requestType'};
	
	my $answerResolution = undef;
	
	if(exists($RequestClass{$requestType})) {
		my $methodName = $RequestClass{$requestType}{'method'};
		return $self->$methodName($requestPayload,$answerPayload);
	}
	
	return undef;
}

sub getRequestView($) {
	my $self = shift;
	
	my($requestType) = @_;
	
	my $viewDir = undef;
	
	if(exists($RequestClass{$requestType})) {
		# TODO
		$viewDir = $RequestClass{$requestType}{'view'};
	}
	
	return $viewDir;
}

sub getDesistView($) {
	my $self = shift;
	
	my($requestType) = @_;
	
	my $desistViewDir = undef;
	
	if(exists($RequestClass{$requestType})) {
		# TODO
		$desistViewDir = $RequestClass{$requestType}{'desistView'};
	}
	
	return $desistViewDir;
}


# Generate both the request and desist links
# Parameters:
#	requestId:
#	desistCode:
# It returns a two-element array, with the links
sub genLinksFromReq($$) {
	my $self = shift;
	
	my($requestId,$desistCode) = @_;
	
	my $requestlink = $self->{'publicBaseURI'} . '/' . $requestId . '/';
	my $desistlink = $self->{'publicBaseURI'} . '/' . $requestId . '/desist/' . $desistCode . '/';
	
	return wantarray ? ($requestlink,$desistlink) : $requestlink;
}

1;

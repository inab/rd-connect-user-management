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
		# TODO
	}
	
	return $pass;
}

sub GetMailManagementInstance($$\%;\@) {
	my($cfg,$mailTemplate,$p_keyvals,$p_attachmentFiles) = @_;
	
	# Mail configuration parameters
	return RDConnect::MailManagement->new($cfg,$mailTemplate,$p_keyvals,$p_attachmentFiles);
}

sub ResetUserPassword($$$) {
	my($uMgmt,$userId,$userPassword) = @_;
	
	my $cfg = $uMgmt->getCfg();
	
	unless(defined($userPassword)) {
		$userPassword = GetRandomPassword($cfg);
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
		my $mail2 = GetMailManagementInstance($cfg,\$passMailTemplate,%keyval2);
		$mail2->setSubject('RD-Connect password reset for user '.$userId);
		
		my $fullname = $payload->[0]{'cn'};
		my $email = $payload->[0]{'email'}[0];
		my $to = Email::Address->new($fullname => $email);
		
		$keyval2{'password'} = $userPassword;
		eval {
			$mail2->sendMessage($to,\%keyval2);
		};
		if($@) {
			$retval = {'reason' => 'Error while sending reset password e-mail','trace' => $@};
		}
	} else {
		$retval = {'reason' => 'Error while resetting user password for user '.$userId,'trace' => $payload};
	}
	
	#send_file(\$data, content_type => 'image/jpeg');
	return $retval;
}

1;
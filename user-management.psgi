#!/usr/bin/perl
# RD-Connect User Management REST API
# José María Fernández (jmfernandez@cnio.es)

use strict;
use warnings 'all';

use boolean qw();
use FindBin;
use File::Spec;
use File::Temp qw();
use JSON -no_export;
use URI;

use lib File::Spec->catfile($FindBin::Bin,"libs");

package RDConnect::UserManagement::DancerCommon;

use constant API_CONFIG_DIRNAME	=>	'configs';
use constant API_CONFIG_FILENAME	=>	'user-management.ini';
use constant API_CONFIG_FILE	=>	File::Spec->catfile($FindBin::Bin,API_CONFIG_DIRNAME,API_CONFIG_FILENAME);

{
	use Config::IniFiles;
	
	my $cfg = undef;
	
	sub getRDConnectConfig() {
		unless(defined($cfg)) {
			# Now, let's read all the parameters
			$cfg = Config::IniFiles->new( -file => API_CONFIG_FILE);
		}
		
		return $cfg;
	}
	
	use constant UMGMT_API_SECTION	=>	'rdconnect-usermanagement-api';
	use constant DEFAULT_RDCONNECT_CAS_URL	=>	"https://rdconnectcas.rd-connect.eu:9443/cas";
	
	sub getCASurl() {
		my $cfg = getRDConnectConfig();
		
		return $cfg->val(UMGMT_API_SECTION,'cas_url',DEFAULT_RDCONNECT_CAS_URL);
	}
	
	sub getAdminGroups() {
		my $cfg = getRDConnectConfig();
		
		my $retval = ['cn=admin,ou=groups,dc=rd-connect,dc=eu'];
		
		if($cfg->exists(UMGMT_API_SECTION,'admin_group')) {
			my @adminGroups = $cfg->val(UMGMT_API_SECTION,'admin_group');
			$retval = \@adminGroups;
		}
		
		return $retval;
	}
	
	use constant DEFAULT_RDCONNECT_GROUP_CREATOR	=>	'PI';
	
	sub getGroupCreator() {
		my $cfg = getRDConnectConfig();
		
		return $cfg->val(UMGMT_API_SECTION,'group_creator',DEFAULT_RDCONNECT_GROUP_CREATOR);
	}
	
	use RDConnect::UserManagement;
	
	my $uMgmt = undef;
	
	sub getUserManagementInstance() {
		unless(defined($cfg) && defined($uMgmt)) {
			# Now, let's read all the parameters
			my $cfg = getRDConnectConfig();
			
			# LDAP configuration
			$uMgmt = RDConnect::UserManagement->new($cfg);
		}
		
		return $uMgmt;
	}
	
	use RDConnect::MetaUserManagement;
	
	sub getMailManagementInstance($\%;\@) {
		my($mailTemplate,$p_keyvals,$p_attachmentFiles) = @_;
		
		$p_attachmentFiles = []  unless(defined($p_attachmentFiles));
		
		# Mail configuration parameters
		return RDConnect::MetaUserManagement::GetMailManagementInstance(getRDConnectConfig(),$mailTemplate,%{$p_keyvals},@{$p_attachmentFiles});
	}
}

our $jserr = JSON->new->convert_blessed();

1;

package RDConnect::UserManagement::API;

use Dancer2;
use Dancer2::Serializer::JSON;
use Dancer2::Session::YAML;
use Dancer2::Plugin::Auth::CAS;
use Dancer2::Plugin::Auth::RDConnect;

set engines => {
	'serializer' => {
		'JSON' => {
			'convert_blessed' => 1,
			'utf8'	=>	0
		}
	},
	'deserializer' => {
		'JSON' => {
			'utf8'	=>	0
		}
	},
	'session' => {
		'YAML' => {
			'session_config' => {
				'cookie_name' => 'rd.umgmt.api',
				'cookie_duration'	=>	'1 hour',
				'session_duration'	=>	'1 hour'
			},
			'session_dir' => '/tmp/.RDConnect-UserManagement-API-sessions_'.$<
		}
	}
};

use constant CAS_USER_MAP	=>	"user";
use constant MEMBEROF_ATTRIBUTE	=>	"memberOf";
use constant USERNAME_ATTRIBUTE	=>	"username";
use constant USER_CATEGORY_ATTRIBUTE	=>	'userCategory';

set plugins => {
	"Auth::CAS" => {
		ssl_verify_hostname	=>	0,
		cas_url => RDConnect::UserManagement::DancerCommon::getCASurl(),
		cas_denied_path => "/denied",
		cas_version => "3.0",
#		cas_version => "2.0",
		cas_user_map => CAS_USER_MAP,
		cas_attr_map => {
		#	email => "email",
			uid => USERNAME_ATTRIBUTE,
			userClass => USER_CATEGORY_ATTRIBUTE,
		#	firstName => "firstname",
		#	lastName => "lastname"
		},
		cas_attr_as_array_map => {
			MEMBEROF_ATTRIBUTE()	=>	1
		}
	},
	"Auth::RDConnect" => {
		cas_user_map => CAS_USER_MAP,
		username_attribute	=>	USERNAME_ATTRIBUTE,
		groups_attribute	=>	MEMBEROF_ATTRIBUTE,
		userCategory_attribute	=>	USER_CATEGORY_ATTRIBUTE,
		rdconnect_admin_groups	=>	RDConnect::UserManagement::DancerCommon::getAdminGroups(),
		rdconnect_group_creator	=>	RDConnect::UserManagement::DancerCommon::getGroupCreator(),
		uMgmt	=>	RDConnect::UserManagement::DancerCommon::getUserManagementInstance()
	}
};

# Order DOES matter!
set session => 'YAML';
set serializer => 'JSON';
set charset => 'UTF-8';

# Basic information #

get '/'	=> sub {
	return {
		'cas_login'	=>	RDConnect::UserManagement::DancerCommon::getCASurl() . '/login',
		'cas_logout'	=>	RDConnect::UserManagement::DancerCommon::getCASurl() . '/logout',
	};
};

post '/login' => auth_cas pre_auth => sub {
	my $retval = vars->{CAS_USER_MAP()};
	$retval->{'session_id'} = vars->{'api_session_id'};
	return $retval;
};

get '/login' => auth_cas login => sub {
	return vars->{CAS_USER_MAP()};
};

get '/logout' => auth_cas logout => sub {
	return {};
};


#########################
# Mail common functions #
#########################
sub dataUrl2TmpFile {
	my($baseDir,$dataUrl,$num) = @_;
	
	my $datauri = URI->new($dataUrl);
	
	# Only data protocol
	return undef  unless($datauri->scheme() eq 'data');
	
	my $filename;
	
	# Extracting the filename (if possible)
	if($dataUrl =~ /^data:(?:[^\/]+\/[^\/]+;)name=([^;]+);/) {
		$filename = $1;
	} else {
		$filename = 'Attachment_'.$num;
	}
	
	my $retval = File::Spec->catfile($baseDir,$filename);
	
	if(open(my $T,'>:raw',$retval)) {
		print $T $datauri->data();
		
		close($T);
	} else {
		$retval = undef;
	}
	
	return wantarray?($retval,$datauri->media_type()):$retval;
}

sub send_email {
	my($subject,$mailTemplate,$p_attachmentFiles,$p_users,$p_groups,$p_organizationalUnits) = @_;
	
	my %keyval1 = ( 'username' => '(undefined)', 'fullname' => '(undefined)' );
	
	my $mail1;
	# Mail configuration parameters
	$mail1 = RDConnect::UserManagement::DancerCommon::getMailManagementInstance($mailTemplate,%keyval1,@{$p_attachmentFiles});
	$mail1->setSubject($subject);
	
	# LDAP configuration
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my @errlist = ();
	
	# Read the users
	my @users = ();
	my $doAll = 1;
	if(ref($p_users) eq 'ARRAY' && scalar(@{$p_users}) > 0) {
		$doAll = undef;
		
		foreach my $username (@{$p_users}) {
			my($success,$payload) = $uMgmt->getUser($username);
			if($success) {
				push(@users,$payload);
			} else {
				push(@errlist,"Unable to find user $username. Does it exist?");
			}
		}
	}
	
	if(ref($p_groups) eq 'ARRAY' && scalar(@{$p_groups}) > 0) {
		$doAll = undef;
		
		foreach my $groupName (@{$p_groups}) {
			my($success,$payload) = $uMgmt->getGroupMembers($groupName);
			if($success) {
				push(@users,@{$payload});
			} else {
				push(@errlist,"Unable to find group / role $groupName. Does it exist?");
			}
		}
	}
	
	if(ref($p_organizationalUnits) eq 'ARRAY' && scalar(@{$p_organizationalUnits}) > 0) {
		$doAll = undef;
		
		foreach my $ouName (@{$p_organizationalUnits}) {
			my($success,$payload) = $uMgmt->listPeopleOUUsers($ouName);
			if($success) {
				push(@users,@{$payload});
			} else {
				push(@errlist,"Unable to find organizational unit $ouName. Does it exist?");
			}
		}
	}
	
	if($doAll) {
		my($success,$payload) = $uMgmt->listUsers();
		if($success) {
			@users = @{$payload};
		} else {
			push(@errlist,"Internal error: unable to fetch all the users");
		}
	}
	
	my @filteredUsers = ();
	foreach my $user (@users) {
		# Don't send the e-mail to disabled accounts
		next  if($user->get_value('disabledAccount') eq 'TRUE');
		
		push(@filteredUsers,$user);
	}
	
	# TODO: do this in background
	foreach my $user (@filteredUsers) {
		# Don't send the e-mail to disabled accounts
		next  if($user->get_value('disabledAccount') eq 'TRUE');
		
		my $username = $user->get_value('uid');
		my $fullname = $user->get_value('cn');
		my $email = $user->get_value('mail');
		# Re-defining the object
		my $to = Email::Address->new($fullname => $email);
		
		$keyval1{'username'} = $username;
		$keyval1{'fullname'} = $fullname;
		eval {
			$mail1->sendMessage($to,\%keyval1);
		};
		
		if($@) {
			Carp::carp("Error while sending e-mail to $username ($email): ",$@);
		}
	}
	
	return \@errlist;
}

sub send_email_base64 {
	my($subject,$mailTemplateBase64,$p_attachmentsBase64,$p_users,$p_groups,$p_organizationalUnits) = @_;
	
	# First, let's save the file contents in real files (in a temporal directory)
	my $tempdir = File::Temp->newdir(TMPDIR => 1);
	
	my($mailTemplate,$mailTemplateMime) = dataUrl2TmpFile($tempdir->dirname,$mailTemplateBase64,0);
	my @attachmentFiles = ();
	if(ref($p_attachmentsBase64) eq 'ARRAY') {
		my $counter = 0;
		foreach my $attachmentBase64 (@{$p_attachmentsBase64}) {
			$counter++;
			my $filename = dataUrl2TmpFile($tempdir->dirname,$attachmentBase64,$counter);
			push(@attachmentFiles,$filename)  if(defined($filename));
		}
	}
	
	return send_email($subject,{'template'=>$mailTemplate,'mime'=>$mailTemplateMime},\@attachmentFiles,$p_users,$p_groups,$p_organizationalUnits);
}

# Now, the methods
sub get_mail_json_schema {
	if(exists(query_parameters->{'schema'})) {
		return send_file(RDConnect::UserManagement::FULL_RDDOCUMENT_VALIDATION_SCHEMA_FILE, system_path => 1);
	}
	
	pass;
}

sub list_newUser_documents {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my($success,$payload) = $uMgmt->listJSONDocumentsFromDomain(RDConnect::UserManagement::NewUserDomain);
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Mail templates for new users not found','trace' => $payload}),404);
	}
	
	# Here the payload
	return $payload;
}

sub get_newUser_document {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my($success,$payload) = $uMgmt->getDocumentFromDomain(RDConnect::UserManagement::NewUserDomain,params->{document_name});
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Mail templates not found','trace' => $payload}),404);
	} elsif(!defined($payload)) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Mail templates do not have document '.params->{document_name}}),404);
	}
	
	# Here the payload is the document
	my $data = $payload->get_value('content');
	send_file(\$data, content_type => $payload->get_value('mimeType'));
}

sub get_newUser_document_metadata {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my($success,$payload) = $uMgmt->getJSONDocumentMetadataFromDomain(RDConnect::UserManagement::NewUserDomain,params->{document_name});
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Mail templates not found','trace' => $payload}),404);
	} elsif(!defined($payload)) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Mail templates do not have document '.params->{document_name}}),404);
	}
	
	return $payload;
}


sub modify_newUser_document_metadata {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my $p_newMetadata = request->data;
	
	my($success,$payload) = $uMgmt->modifyJSONDocumentMetadataFromDomain(RDConnect::UserManagement::NewUserDomain,params->{document_name},$p_newMetadata);
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Error while modifying document '.params->{document_name}.' from mail templates','trace' => $payload}),500);
	}
	
	#send_file(\$data, content_type => 'image/jpeg');
	return [];
}

sub modify_newUser_document {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	# We are getting the raw entry, as we want just the photo
	my $data = request->body;
	
	my($success,$payload) = $uMgmt->modifyDocumentFromDomain(RDConnect::UserManagement::NewUserDomain,params->{'document_name'},$data);
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Mail templates not found','trace' => $payload}),404);
	}
	
	#send_file(\$data, content_type => 'image/jpeg');
	return [];
}

sub attach_newUser_document {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my %documentMetadata = (
		'cn'	=> params->{'cn'},
	);
	$documentMetadata{'description'} = params->{'description'}  if(exists(params->{'description'}));
	$documentMetadata{'documentClass'} = params->{'documentClass'}  if(exists(params->{'documentClass'}));
	
	my($success,$payload) = $uMgmt->attachDocumentForDomain(RDConnect::UserManagement::NewUserDomain,\%documentMetadata,upload('content')->content);
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Mail templates not found','trace' => $payload}),404);
	}
	
	#send_file(\$data, content_type => 'image/jpeg');
	return [];
}

sub remove_newUser_document {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my($success,$payload) = $uMgmt->removeDocumentFromDomain(RDConnect::UserManagement::NewUserDomain,params->{'document_name'});
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Mail templates not found','trace' => $payload}),404);
	}
	
	#send_file(\$data, content_type => 'image/jpeg');
	return [];
}

sub broadcast_email {
	my %newMail = params;
	
	my $retval = send_email_base64($newMail{'subject'},$newMail{'mailTemplate'},$newMail{'attachments'},$newMail{'users'},$newMail{'groups'},$newMail{'organizationalUnits'});
	
	return $retval;
}




prefix '/mail' => sub {
	get '' => \&get_mail_json_schema;
	
	post '' => auth_cas login => rdconnect_auth admin => \&broadcast_email;
	
	# Mail templates
	prefix '/newUser/documents' => sub {
		get '' => auth_cas login => \&list_newUser_documents;
		post '' => auth_cas login => rdconnect_auth admin => \&attach_newUser_document;
		get '/:document_name' => auth_cas login => rdconnect_auth admin => \&get_newUser_document;
		put '/:document_name' => auth_cas login => rdconnect_auth admin => \&modify_newUser_document;
		del '/:document_name' => auth_cas login => rdconnect_auth admin => \&remove_newUser_document;
		get '/:document_name/metadata' => auth_cas login => rdconnect_auth admin => \&get_newUser_document_metadata;
		post '/:document_name/metadata' => auth_cas login => rdconnect_auth admin => \&modify_newUser_document_metadata;
	};
};

#########
# Users #
#########

sub get_users {
	if(exists(query_parameters->{'schema'})) {
		return send_file(RDConnect::UserManagement::FULL_USER_VALIDATION_SCHEMA_FILE, system_path => 1);
	}
	
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my($success,$payload) = $uMgmt->listJSONUsers();
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Could not fulfill internal queries','trace' => $payload}),500);
	}
	
	# Here the payload is the list of users
	return $payload;
}

sub get_user {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my($success,$payload) = $uMgmt->getJSONUser(params->{user_id});
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'User '.params->{user_id}.' not found','trace' => $payload}),404);
	}
	
	# Here the payload is the user
	return $payload;
}

sub get_user_photo {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	# We are getting the raw entry, as we don't want to encode / decode the entry, only the photo
	my($success,$payload) = $uMgmt->getUser(params->{user_id});
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'User '.params->{user_id}.' not found','trace' => $payload}),404);
	} elsif(! $payload->exists('jpegPhoto')) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'User '.params->{user_id}.' does not have photo'}),404);
	}
	
	# Here the payload is the user
	my $data = $payload->get_value('jpegPhoto');
	send_file(\$data, content_type => 'image/jpeg');
}

sub get_user_groups {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my($success,$payload) = $uMgmt->getJSONUserGroups(params->{user_id});
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'User '.params->{user_id}.' not found','trace' => $payload}),404);
	}
	
	# Here the payload is the list of groups
	return $payload;
}

sub get_user_group {
	redirect '../../groups/'.params->{'group_id'}, 301;
}

sub list_user_documents {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my($success,$payload) = $uMgmt->listJSONDocumentsFromUser(params->{user_id});
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Documents from user '.params->{user_id}.' not found','trace' => $payload}),404);
	}
	
	# Here the payload is the list of groups
	return $payload;
}

sub get_user_document {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my($success,$payload) = $uMgmt->getDocumentFromUser(params->{user_id},params->{document_name});
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'User '.params->{user_id}.' not found','trace' => $payload}),404);
	} elsif(!defined($payload)) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'User '.params->{user_id}.' does not have document '.params->{document_name}}),404);
	}
	
	# Here the payload is the document
	my $data = $payload->get_value('content');
	send_file(\$data, content_type => $payload->get_value('mimeType'));
}

sub get_user_document_metadata {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my($success,$payload) = $uMgmt->getJSONDocumentMetadataFromUser(params->{user_id},params->{document_name});
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'User '.params->{user_id}.' not found','trace' => $payload}),404);
	} elsif(!defined($payload)) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'User '.params->{user_id}.' does not have document '.params->{document_name}}),404);
	}
	
	return $payload;
}

# next operations should be allowed only to privileged users

sub create_user {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my %newUser = params;
	my $retval = RDConnect::MetaUserManagement::CreateUser($uMgmt,%newUser);
	
	send_error($RDConnect::UserManagement::DancerCommon::jserr->encode($retval),exists($retval->{'code'}) ? $retval->{'code'}:500)  if(defined($retval));
	
	return [];
}

sub modify_user {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my $p_newUser = request->data;
	
	my($success,$payload) = $uMgmt->modifyJSONUser(params->{user_id},$p_newUser);
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Error while modifying user '.params->{user_id},'trace' => $payload}),500);
	}
	
	#send_file(\$data, content_type => 'image/jpeg');
	return [];
}

sub put_user_photo {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	# We are getting the raw entry, as we want just the photo
	my $data = request->body;
	
	my($success,$payload) = $uMgmt->setUserPhoto(params->{'user_id'},$data);
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'User '.params->{user_id}.' not found','trace' => $payload}),404);
	}
	
	#send_file(\$data, content_type => 'image/jpeg');
	return [];
}

sub set_user_enabled_state {
	my $newState = shift;
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my($success,$payload) = $uMgmt->enableUser(params->{user_id},$newState);
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'User '.params->{user_id}.' not found','trace' => $payload}),404);
	}
	
	return [];
}

sub disable_user {
	return set_user_enabled_state(boolean::false);
}

sub enable_user {
	return set_user_enabled_state(boolean::true);
}

sub reset_user_password {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my %newUser = params;
	
	my $retval = RDConnect::MetaUserManagement::ResetUserPassword($uMgmt,params->{'user_id'},exists($newUser{'userPassword'})?$newUser{'userPassword'}:undef);
	
	send_error($RDConnect::UserManagement::DancerCommon::jserr->encode($retval),exists($retval->{'code'}) ? $retval->{'code'}:500)  if(defined($retval));
	
	return [];
}

sub add_user_to_groups {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my %newGroups = params;
	# We remove so we don't disturb with garbage
	delete $newGroups{'user_id'};
	
	my $p_newGroups = request->data;
	
	my($success,$payload) = $uMgmt->addMemberToGroup(params->{user_id},$p_newGroups);
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Error while adding user '.params->{user_id}.' to groups','trace' => $payload}),500);
	}
	
	return [];
}

sub remove_user_from_groups {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my %newGroups = params;
	# We remove so we don't disturb with garbage
	delete $newGroups{'user_id'};
	
	my $p_groupsToRemove = request->data;
	
	my($success,$payload) = $uMgmt->removeMemberFromGroup(params->{user_id},$p_groupsToRemove);
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Error while removing user '.params->{user_id}.' from groups','trace' => $payload}),500);
	}
	
	#send_file(\$data, content_type => 'image/jpeg');
	return [];
}

sub modify_user_document_metadata {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my $p_newMetadata = request->data;
	
	my($success,$payload) = $uMgmt->modifyJSONDocumentMetadataFromUser(params->{user_id},params->{document_name},$p_newMetadata);
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Error while modifying document '.params->{document_name}.' from user '.params->{user_id},'trace' => $payload}),500);
	}
	
	#send_file(\$data, content_type => 'image/jpeg');
	return [];
}

sub modify_user_document {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	# We are getting the raw entry, as we want just the photo
	my $data = request->body;
	
	my($success,$payload) = $uMgmt->modifyDocumentFromUser(params->{'user_id'},params->{'document_name'},$data);
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'User '.params->{user_id}.' not found','trace' => $payload}),404);
	}
	
	#send_file(\$data, content_type => 'image/jpeg');
	return [];
}

sub attach_user_document {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my %documentMetadata = (
		'cn'	=> params->{'cn'},
	);
	$documentMetadata{'description'} = params->{'description'}  if(exists(params->{'description'}));
	$documentMetadata{'documentClass'} = params->{'documentClass'}  if(exists(params->{'documentClass'}));
	
	my($success,$payload) = $uMgmt->attachDocumentForUser(params->{'user_id'},\%documentMetadata,upload('content')->content);
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'User '.params->{user_id}.' not found','trace' => $payload}),404);
	}
	
	#send_file(\$data, content_type => 'image/jpeg');
	return [];
}

sub remove_user_document {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my($success,$payload) = $uMgmt->removeDocumentFromUser(params->{'user_id'},params->{'document_name'});
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'User '.params->{user_id}.' not found','trace' => $payload}),404);
	}
	
	#send_file(\$data, content_type => 'image/jpeg');
	return [];
}

sub mail_user {
	my %newMail = params;
	
	my $retval = send_email_base64($newMail{'subject'},$newMail{'mailTemplate'},$newMail{'attachments'},[$newMail{'user_id'}]);
	
	return $retval;
}


# Routing for /users prefix
prefix '/users' => sub {
	get '' => \&get_users;
	get '/:user_id' => => \&get_user;
	get '/:user_id/picture' => \&get_user_photo;
	get '/:user_id/groups' => \&get_user_groups;
	get '/:user_id/groups/:group_id' => \&get_user_group;
	# next operations should be allowed only to privileged users
	put '' => auth_cas login => rdconnect_auth PI => \&create_user;
	post '/:user_id' => auth_cas login => rdconnect_auth user => \&modify_user;
	put '/:user_id/picture' => auth_cas login => rdconnect_auth user => \&put_user_photo;
	post '/:user_id/disable' => auth_cas login => rdconnect_auth user => \&disable_user;
	post '/:user_id/enable' => auth_cas login => rdconnect_auth admin => \&enable_user;
	post '/:user_id/resetPassword' => auth_cas login => rdconnect_auth user => \&reset_user_password;
	post '/:user_id/groups' => auth_cas login => rdconnect_auth admin => \&add_user_to_groups;
	del '/:user_id/groups' => auth_cas login => rdconnect_auth user => \&remove_user_from_groups;
	
	post '/:user_id/_mail' => auth_cas login => rdconnect_auth user => \&mail_user;
	
	# Legal documents related to the user
	prefix '/:user_id/documents' => sub {
		get '' => auth_cas login => \&list_user_documents;
		post '' => auth_cas login => rdconnect_auth user => \&attach_user_document;
		get '/:document_name' => auth_cas login => rdconnect_auth user => \&get_user_document;
		put '/:document_name' => auth_cas login => rdconnect_auth user => \&modify_user_document;
		del '/:document_name' => auth_cas login => rdconnect_auth user => \&remove_user_document;
		get '/:document_name/metadata' => auth_cas login => rdconnect_auth user => \&get_user_document_metadata;
		post '/:document_name/metadata' => auth_cas login => rdconnect_auth user => \&modify_user_document_metadata;
	};
};

#################
# Enabled Users #
#################

sub get_enabled_users {
	if(exists(query_parameters->{'schema'})) {
		return send_file(RDConnect::UserManagement::FULL_ENABLED_USERS_SCHEMA_FILE, system_path => 1);
	}
	
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my($success,$payload) = $uMgmt->listJSONEnabledUsers();
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Could not fulfill internal queries','trace' => $payload}),500);
	}
	
	# Here the payload is the list of users
	return $payload;
}
prefix '/enabledUsers' => sub {
	get '' => \&get_enabled_users;
};

########################
# Organizational units #
########################

sub get_OUs {
	if(exists(query_parameters->{'schema'})) {
		return send_file(RDConnect::UserManagement::FULL_OU_VALIDATION_SCHEMA_FILE, system_path => 1);
	}
	
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my($success,$payload) = $uMgmt->listJSONPeopleOU();
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Could not fulfill internal queries','trace' => $payload}),500);
	}
	
	# Here the payload is the list of organizational units
	return $payload;
}

sub get_OU {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my($success,$payload) = $uMgmt->getJSONPeopleOU(params->{ou_id});
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Organizational unit '.params->{ou_id}.' not found','trace' => $payload}),404);
	}
	
	# Here the payload is the organizational unit
	return $payload;
}

sub get_OU_users {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my($success,$payload) = $uMgmt->listJSONPeopleOUUsers(params->{ou_id});
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Organizational unit '.params->{ou_id}.' not found','trace' => $payload}),404);
	}
	
	# Here the payload are the users
	return $payload;
}

sub get_OU_user {
	redirect '../../users/'.params->{user_id}, 301;
}

sub get_OU_photo {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	# We are getting the raw entry, as we don't want to encode / decode the entry, only the photo
	my($success,$payload) = $uMgmt->getPeopleOU(params->{ou_id});
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Organizational unit '.params->{ou_id}.' not found','trace' => $payload}),404);
	} elsif(! $payload->exists('jpegPhoto')) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Organizational unit '.params->{ou_id}.' does not have photo'}),404);
	}
	
	# Here the payload is the user
	my $data = $payload->get_value('jpegPhoto');
	send_file(\$data, content_type => 'image/jpeg');
}


# next operations should be allowed only to privileged users

sub create_OU {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my %newOU = params;
	
	my($success,$payload) = $uMgmt->createExtPeopleOU(\%newOU);
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Error while creating organizational unit','trace' => $payload}),500);
	}
	
	#send_file(\$data, content_type => 'image/jpeg');
	return [];
}

sub modify_OU {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my %newOU = params;
	# We remove so we don't disturb with garbage
	delete $newOU{ou_id};
	
	my($success,$payload) = $uMgmt->modifyJSONPeopleOU(params->{ou_id},\%newOU);
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Error while modifying organizational unit '.params->{ou_id},'trace' => $payload}),500);
	}
	
	#send_file(\$data, content_type => 'image/jpeg');
	return [];
}

sub put_OU_photo {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	# We are getting the raw entry, as we want just the photo
	my $data = request->body;
	
	my($success,$payload) = $uMgmt->setPeopleOUPhoto(params->{ou_id},$data);
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Organizational unit '.params->{ou_id}.' not found','trace' => $payload}),404);
	}
	
	#send_file(\$data, content_type => 'image/jpeg');
	return [];
}

sub mail_organizationalUnit {
	my %newMail = params;
	
	my $retval = send_email_base64($newMail{'subject'},$newMail{'mailTemplate'},$newMail{'attachments'},undef,undef,[$newMail{'ou_id'}]);
	
	return $retval;
}

prefix '/organizationalUnits' => sub {
	get '' => \&get_OUs;
	get '/:ou_id' => \&get_OU;
	get '/:ou_id/picture' => \&get_OU_photo;
	get '/:ou_id/users' => \&get_OU_users;
	get '/:ou_id/users/:user_id' => \&get_OU_user;
	# next operations should be allowed only to privileged users
	put '' => auth_cas login => rdconnect_auth admin => \&create_OU;
	post '/:ou_id' => auth_cas login => rdconnect_auth admin => \&modify_OU;
	put '/:ou_id/picture' => auth_cas login => rdconnect_auth admin => \&put_OU_photo;
	
	post '/:ou_id/users/_mail' => auth_cas login => rdconnect_auth PI => \&mail_organizationalUnit;
};

##################
# Groups / roles #
##################

sub get_groups {
	if(exists(query_parameters->{'schema'})) {
		return send_file(RDConnect::UserManagement::FULL_GROUP_VALIDATION_SCHEMA_FILE, system_path => 1);
	}
	
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my($success,$payload) = $uMgmt->listJSONGroups();
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Could not fulfill internal queries','trace' => $payload}),500);
	}
	
	# Here the payload is the list of organizational units
	return $payload;
}

sub get_group {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my($success,$payload) = $uMgmt->getJSONGroup(params->{group_id});
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Group '.params->{group_id}.' not found','trace' => $payload}),404);
	}
	
	# Here the payload is the group
	return $payload;
}

sub get_group_members {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my($success,$payload) = $uMgmt->getJSONGroupMembers(params->{group_id});
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Group '.params->{group_id}.' not found','trace' => $payload}),404);
	}
	
	# Here the payload are the users
	return $payload;
}

sub get_group_owners {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my($success,$payload) = $uMgmt->getJSONGroupOwners(params->{group_id});
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Group '.params->{group_id}.' not found','trace' => $payload}),404);
	}
	
	# Here the payload are the users
	return $payload;
}

sub list_group_documents {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my($success,$payload) = $uMgmt->listJSONDocumentsFromGroup(params->{group_id});
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Group '.params->{group_id}.' not found','trace' => $payload}),404);
	} elsif(!defined($payload)) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Group '.params->{group_id}.' does not have document '.params->{document_name}}),404);
	}
	
	# Here the payload is the list of groups
	return $payload;
}

sub get_group_document {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my($success,$payload) = $uMgmt->getDocumentFromUser(params->{user_id},params->{document_name});
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Group '.params->{group_id}.' not found','trace' => $payload}),404);
	} elsif(!defined($payload)) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Group '.params->{group_id}.' does not have document '.params->{document_name}}),404);
	}
	
	# Here the payload is the document
	my $data = $payload->get_value('content');
	send_file(\$data, content_type => $payload->get_value('mimeType'));
}

# next operations should be allowed only to allowed / privileged users

sub create_group {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my $p_newGroup = request->data;
	
	my($success,$payload) = $uMgmt->createExtGroup($p_newGroup);
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Error while creating group','trace' => $payload}),500);
	}
	
	#send_file(\$data, content_type => 'image/jpeg');
	return [];
}

sub modify_group {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my $p_newGroup = request->data;
	
	my($success,$payload) = $uMgmt->modifyJSONGroup(params->{group_id},$p_newGroup);
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Error while modifying group '.params->{group_id},'trace' => $payload}),500);
	}
	
	#send_file(\$data, content_type => 'image/jpeg');
	return [];
}

sub add_group_users {
	my $isOwner = shift;
	
	my $p_newUsers = request->data;
	
	send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Input must be an array'}),500)  unless(ref($p_newUsers) eq 'ARRAY');
	
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my $p_newGroups = [ params->{group_id} ];
	
	foreach my $user_id (@{$p_newUsers}) {
		next  unless(defined($user_id));
		
		my($success,$payload) = $uMgmt->addUserToGroup($user_id,$isOwner,$p_newGroups);
		
		unless($success) {
			send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Error while adding user '.$user_id.' to group '.params->{group_id},'trace' => $payload}),500);
		}
	}
	
	#send_file(\$data, content_type => 'image/jpeg');
	return [];
}

sub add_group_members {
	return add_group_users();
}

sub add_group_owners {
	return add_group_users(1);
}


sub remove_users_from_group {
	my $isOwner = shift;
	
	my $p_newUsers = request->data;
	
	send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Input must be an array'}),500)  unless(ref($p_newUsers) eq 'ARRAY');
	
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my $p_newGroups = [ params->{group_id} ];
	
	foreach my $user_id (@{$p_newUsers}) {
		next  unless(defined($user_id));
		
		my($success,$payload) = $uMgmt->removeUserFromGroup($user_id,$isOwner,$p_newGroups);
		
		unless($success) {
			send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Error while removing user '.$user_id.' from group '.params->{group_id},'trace' => $payload}),500);
		}
	}
	
	#send_file(\$data, content_type => 'image/jpeg');
	return [];
}

sub remove_group_members {
	return remove_users_from_group();
}

sub remove_group_owners {
	return remove_users_from_group(1);
}

sub modify_group_document_metadata {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my $p_newMetadata = request->data;
	
	my($success,$payload) = $uMgmt->modifyJSONDocumentMetadataFromGroup(params->{group_id},params->{document_name},$p_newMetadata);
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Error while modifying document '.params->{document_name}.' from group '.params->{group_id},'trace' => $payload}),500);
	}
	
	#send_file(\$data, content_type => 'image/jpeg');
	return [];
}

sub modify_group_document {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	# We are getting the raw entry, as we want just the photo
	my $data = request->body;
	
	my($success,$payload) = $uMgmt->modifyDocumentFromGroup(params->{'group_id'},params->{'document_name'},$data);
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Group '.params->{group_id}.' not found','trace' => $payload}),404);
	}
	
	#send_file(\$data, content_type => 'image/jpeg');
	return [];
}

sub attach_group_document {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my %documentMetadata = (
		'cn'	=> params->{'cn'},
	);
	$documentMetadata{'description'} = params->{'description'}  if(exists(params->{'description'}));
	$documentMetadata{'documentClass'} = params->{'documentClass'}  if(exists(params->{'documentClass'}));
	
	my($success,$payload) = $uMgmt->attachDocumentForGroup(params->{'group_id'},\%documentMetadata,upload('content')->content);
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Group '.params->{group_id}.' not found','trace' => $payload}),404);
	}
	
	#send_file(\$data, content_type => 'image/jpeg');
	return [];
}

sub remove_group_document {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my($success,$payload) = $uMgmt->removeDocumentFromGroup(params->{'group_id'},params->{'document_name'});
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Group '.params->{group_id}.' not found','trace' => $payload}),404);
	}
	
	#send_file(\$data, content_type => 'image/jpeg');
	return [];
}

sub mail_group {
	my %newMail = params;
	
	my $retval = send_email_base64($newMail{'subject'},$newMail{'mailTemplate'},$newMail{'attachments'},undef,[$newMail{'group_id'}]);
	
	return $retval;
}


prefix '/groups' => sub {
	get '' => \&get_groups;
	get '/:group_id' => \&get_group;
	get '/:group_id/members' => \&get_group_members;
	get '/:group_id/owners' => \&get_group_owners;
	# next operations should be allowed only to allowed / privileged users
	put '' => auth_cas login => rdconnect_auth PI => \&create_group;
	post '/:group_id' => auth_cas login => rdconnect_auth owner => \&modify_group;
	post '/:group_id/members' => auth_cas login => rdconnect_auth owner => \&add_group_members;
	del '/:group_id/members' => auth_cas login => rdconnect_auth owner => \&remove_group_members;
	
	post '/:group_id/members/_mail' => auth_cas login => rdconnect_auth owner => \&mail_group;
	
	post '/:group_id/owners' => auth_cas login => rdconnect_auth owner => \&add_group_owners;
	del '/:group_id/owners' => auth_cas login => rdconnect_auth owner => \&remove_group_owners;
	
	prefix '/:group_id/documents' => sub {
		get '' => auth_cas login => rdconnect_auth owner => \&list_group_documents;
		post '' => auth_cas login => rdconnect_auth owner => \&attach_group_document;
		get '/:document_name' => auth_cas login => rdconnect_auth owner => \&get_group_document;
		put '/:document_name' => auth_cas login => rdconnect_auth owner => \&modify_group_document;
		del '/:document_name' => auth_cas login => rdconnect_auth owner => \&remove_group_document;
		get '/:document_name/metadata' => auth_cas login => rdconnect_auth owner => \&get_group_document_metadata;
		post '/:document_name/metadata' => auth_cas login => rdconnect_auth owner => \&modify_group_document_metadata;
	};
};

get 'documents' => sub {
	if(exists(query_parameters->{'schema'})) {
		return send_file(RDConnect::UserManagement::FULL_RDDOCUMENT_VALIDATION_SCHEMA_FILE, system_path => 1);
	}
	
	pass;
};

package main;

use Plack::Builder;
builder {
	# Order does matter!
	enable 'CrossOrigin', origins => '*', headers => '*';
	# When this module is enabled, it introduces a double encoding issue.
	#enable 'Deflater', content_type => ['text/plain','text/css','text/html','text/javascript','application/javascript','application/json'];
	mount '/'    => RDConnect::UserManagement::API->to_app;
};

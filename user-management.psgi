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

use lib File::Spec->catfile($FindBin::Bin,"libs");

package RDConnect::UserManagement::DancerCommon;

use constant API_CONFIG_FILENAME	=>	'user-management.ini';
use constant API_CONFIG_FILE	=>	File::Spec->catfile($FindBin::Bin,API_CONFIG_FILENAME);

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
	
	use RDConnect::MailManagement;
	
	sub getMailManagementInstance($\%;\@) {
		my($mailTemplate,$p_keyvals,$p_attachmentFiles) = @_;
		
		# Mail configuration parameters
		return RDConnect::MailManagement->new(getRDConnectConfig(),$mailTemplate,$p_keyvals,$p_attachmentFiles);
	}
}

our $jserr = JSON->new->convert_blessed();

1;

package RDConnect::UserManagement::API;

use Dancer2;
use Dancer2::Serializer::JSON;
use Dancer2::Session::YAML;
use Dancer2::Plugin::Auth::CAS;

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
			'session_dir' => '/tmp/.RDConnect-UserManagement-API-sessions'
		}
	}
};

use constant CAS_USER_MAP	=>	"user";

set plugins => {
	"Auth::CAS" => {
		ssl_verify_hostname	=>	0,
		cas_url => RDConnect::UserManagement::DancerCommon::getCASurl(),
		cas_denied_path => "/denied",
		cas_version => "3.0",
#		cas_version => "2.0",
		cas_user_map => CAS_USER_MAP,
		cas_attr_map => {
			email => "email",
			username => "username",
			firstName => "firstname",
			lastName => "lastname"
		}
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
	
	my($success,$payload) = $uMgmt->createExtUser(\%newUser);
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Error while creating user','trace' => $payload}),500);
	}
	
	#send_file(\$data, content_type => 'image/jpeg');
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
	
	#send_file(\$data, content_type => 'image/jpeg');
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
	
	my($success,$payload) = $uMgmt->modifyDocumentFromUser(params->{'user_id'},params->{'document_name'});
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'User '.params->{user_id}.' not found','trace' => $payload}),404);
	}
	
	#send_file(\$data, content_type => 'image/jpeg');
	return [];
}

# Routing for /users prefix
prefix '/users' => sub {
	get '' => \&get_users;
	get '/:user_id' => => \&get_user;
	get '/:user_id/picture' => \&get_user_photo;
	get '/:user_id/groups' => \&get_user_groups;
	get '/:user_id/groups/:group_id' => \&get_user_group;
	# next operations should be allowed only to privileged users
	put '' => auth_cas login => \&create_user;
	post '/:user_id' => auth_cas login => \&modify_user;
	put '/:user_id/picture' => auth_cas login => \&put_user_photo;
	post '/:user_id/disable' => auth_cas login => \&disable_user;
	post '/:user_id/enable' => auth_cas login => \&enable_user;
	post '/:user_id/groups' => auth_cas login => \&add_user_to_groups;
	del '/:user_id/groups' => auth_cas login => \&remove_user_from_groups;
	
	# Legal documents related to the user
	prefix '/:user_id/documents' => sub {
		get '' => auth_cas login => \&list_user_documents;
		post '' => auth_cas login => \&attach_user_document;
		get '/:document_name' => auth_cas login => \&get_user_document;
		put '/:document_name' => auth_cas login => \&modify_user_document;
		del '/:document_name' => auth_cas login => \&remove_user_document;
		get '/:document_name/metadata' => auth_cas login => \&get_user_document_metadata;
		post '/:document_name/metadata' => auth_cas login => \&modify_user_document_metadata;
	};
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

prefix '/organizationalUnits' => sub {
	get '' => \&get_OUs;
	get '/:ou_id' => \&get_OU;
	get '/:ou_id/picture' => \&get_OU_photo;
	get '/:ou_id/users' => \&get_OU_users;
	get '/:ou_id/users/:user_id' => \&get_OU_user;
	# next operations should be allowed only to privileged users
	put '' => auth_cas login => \&create_OU;
	post '/:ou_id' => auth_cas login => \&modify_OU;
	put '/:ou_id/picture' => auth_cas login => \&put_OU_photo;
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


prefix '/groups' => sub {
	get '' => \&get_groups;
	get '/:group_id' => \&get_group;
	get '/:group_id/members' => \&get_group_members;
	get '/:group_id/owners' => \&get_group_owners;
	# next operations should be allowed only to allowed / privileged users
	put '' => auth_cas login => \&create_group;
	post '/:group_id' => auth_cas login => \&modify_group;
	post '/:group_id/members' => auth_cas login => \&add_group_members;
	del '/:group_id/members' => auth_cas login => \&remove_group_members;
	post '/:group_id/owners' => auth_cas login => \&add_group_owners;
	del '/:group_id/owners' => auth_cas login => \&remove_group_owners;
	
	prefix '/:group_id/documents' => sub {
		get '' => auth_cas login => \&list_group_documents;
		post '' => auth_cas login => \&attach_group_document;
		get '/:document_name' => auth_cas login => \&get_group_document;
		put '/:document_name' => auth_cas login => \&modify_group_document;
		del '/:document_name' => auth_cas login => \&remove_group_document;
		get '/:document_name/metadata' => auth_cas login => \&get_group_document_metadata;
		post '/:document_name/metadata' => auth_cas login => \&modify_group_document_metadata;
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
	enable 'Deflater', content_type => ['text/plain','text/css','text/html','text/javascript','application/javascript','application/json'];
	mount '/'    => RDConnect::UserManagement::API->to_app;
};

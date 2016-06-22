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
			'session_dir' => '/tmp/dancer-rdconnect-sessions'
		}
	}
};

set charset => 'UTF-8';
set serializer => 'JSON';
set session => 'YAML';

#########
# Users #
#########

sub get_users {
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
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'User '.params->{user_id}.' has not photo'}),404);
	}
	
	# Here the payload is the user
	my $data = $payload->get_value('jpegPhoto');
	send_file(\$data, content_type => 'image/jpeg');
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
	
	my %newUser = params;
	# We remove so we don't disturb with garbage
	delete $newUser{user_id};
	
	my($success,$payload) = $uMgmt->modifyJSONUser(params->{user_id},\%newUser);
	
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
	
	my($success,$payload) = $uMgmt->setUserPhoto(params->{user_id},$data);
	
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

# Routing for /users prefix
prefix '/users' => sub {
	get '' => \&get_users;
	get '/:user_id' => \&get_user;
	get '/:user_id/picture' => \&get_user_photo;
	# next operations should be allowed only to privileged users
	put '' => \&create_user;
	post '/:user_id' => \&modify_user;
	put '/:user_id/picture' => \&put_user_photo;
	post '/:user_id/disable' => \&disable_user;
	post '/:user_id/enable' => \&enable_user;
};

########################
# Organizational units #
########################

sub get_OUs {
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
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Organizational unit '.params->{ou_id}.' has not photo'}),404);
	}
	
	# Here the payload is the user
	my $data = $payload->get_value('jpegPhoto');
	send_file(\$data, content_type => 'image/jpeg');
}


# next operations should be allowed only to privileged users

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
	# next operations should be allowed only to privileged users
	put '/:ou_id/picture' => \&put_OU_photo;
	get '/:ou_id/users' => \&get_OU_users;
	get '/:ou_id/users/:user_id' => \&get_OU_user;
};

package main;

use Plack::Builder;
builder {
# Enabling this we get some issues, so disabled for now
#	enable 'Deflater', content_type => ['text/plain','text/css','text/html','text/javascript','application/javascript','application/json'];
	mount '/'    => RDConnect::UserManagement::API->to_app;
};

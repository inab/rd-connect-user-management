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
			'convert_blessed' => 1
		}
	},
	'session' => {
		'YAML' => {
			'session_dir' => '/tmp/dancer-rdconnect-sessions'
		}
	}
};

set serializer => 'JSON';
set session => 'YAML';


sub get_users {
	my $uMgmt = RDConnect::UserManagement::DancerCommon::getUserManagementInstance();
	
	my($success,$payload) = $uMgmt->listJSONUsers();
	
	unless($success) {
		send_error($RDConnect::UserManagement::DancerCommon::jserr->encode({'reason' => 'Could not fulfill internal queries','trace' => $payload}),500);
	}
	
	# Here the payload is the list of users
	return $payload;
}

get '/users' => \&get_users;

package main;

use Plack::Builder;
builder {
	enable 'Deflater', content_type => ['text/plain','text/css','text/html','text/javascript','application/javascript','application/json'];
	mount '/'    => RDConnect::UserManagement::API->to_app;
};

#!/usr/bin/perl
# RD-Connect User Management REST API
# José María Fernández (jose.m.fernandez@bsc.es)

use strict;
use warnings 'all';

use FindBin;
use File::Spec;

use boolean qw();
use File::Temp qw();
use URI;

use RDConnect::UserManagement::DancerCommon;

package RDConnect::UserManagement::Requests;

use Dancer2;
use Dancer2::Plugin::CSRF;
##use Dancer2::Serializer::JSON;
use Dancer2::Serializer::MaybeJSON;
use Dancer2::Session::YAML;

use Scalar::Util qw(blessed);

set engines => {
	'serializer' => {
		'MaybeJSON' => {
			'convert_blessed' => 1,
			'utf8'	=>	0
		},
		'JSON' => {
			'convert_blessed' => 1,
			'utf8'	=>	0
		}
	},
	'deserializer' => {
		'MaybeJSON' => {
			'utf8'	=>	0
		},
		'JSON' => {
			'utf8'	=>	0
		}
	},
	'session' => {
		'YAML' => {
			'session_config' => {
				'cookie_name' => 'rd.umgmt.requests',
				'cookie_duration'	=>	3600,
				'session_duration'	=>	3600
			},
			'session_dir' => '/tmp/.RDConnect-UserManagement-Requests-sessions_'.$<
		}
	}
};

set plugins => {
};

set	public_dir => File::Spec->catdir($FindBin::Bin, 'static_requests');

# Order DOES matter!
set session => 'YAML';
set serializer => 'MaybeJSON';
#set serializer => 'JSON';
set charset => 'UTF-8';

use constant CSRF_HEADER     =>      'X-RDConnect-UserManagement-Request';

get '/' => sub {
#	header(CSRF_HEADER() => get_csrf_token());
	return {'test' => 'worked' };
};

hook before => sub {
	# ..
	if ( request->is_post() ) {
		my $csrf_token = request->header(CSRF_HEADER());
		if ( !$csrf_token || !validate_csrf_token($csrf_token) ) {
			  redirect '/?error=invalid_csrf_token';
		}
		# ...
	}
};

# This rule 
hook after => sub {
	if(request->is_get()) {
		response->push_header(CSRF_HEADER() => get_csrf_token());
	}
};

1;

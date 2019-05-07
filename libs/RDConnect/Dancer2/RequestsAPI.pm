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

use RDConnect::Dancer2::Common;

package RDConnect::Dancer2::RequestsAPI;

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

my $publicDir = File::Spec->catdir($FindBin::Bin, 'static_requests');

set	public_dir => $publicDir;

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

# This method must redirect
get '/:requestId' => sub {
	redirect request->path().'/';
};

# This method must return the view, based on the kind of operation
# There are "special" request ids, for fixed operations, like requesting a password reset
get '/:requestId/' => sub {
	my $requestId = params->{'requestId'};
	
	# Now, try finding the request id
	my $rMgmt = RDConnect::Dancer2::Common::getRequestManagementInstance();
	
	my($found,$payload) = $rMgmt->getRequestPayload($requestId);
	
	unless($found) {
		send_error($RDConnect::Dancer2::Common::jserr->encode({'reason' => "Request not available"}),404);
	}
	
	my $viewDir = $rMgmt->getRequestView($payload->{'requestType'},$payload->{'publicPayload'});
	
	if(defined($viewDir)) {
		send_file(File::Spec->catfile($viewDir,'index.html'));
	} else {
		send_error($RDConnect::Dancer2::Common::jserr->encode({'reason' => "Request not available"}),404);
	}
};

# This method has two purposes:
#	* it must return the public payload used by the view (if any)
#	* it sends the CSRF token to be validated
get '/:requestId/details' => sub {
	my $requestId = params->{'requestId'};
	
	# Now, try finding the request id
	my $rMgmt = RDConnect::Dancer2::Common::getRequestManagementInstance();
	
	my($found,$payload) = $rMgmt->getRequestPayload($requestId);
	
	my $publicPayload = {};
	
	# Give no clue about how it worked
	# Only set up return and the CSRF header when the request is found
	if($found) {
		$publicPayload = $payload->{'publicPayload'};
		$publicPayload->{'desistCode'} = $payload->{'desistCode'};
		my $csrf_token = get_csrf_token();
		header(CSRF_HEADER() => $csrf_token);
	}
	
	return $publicPayload;
};

# This method receives the resolution to the request
post '/:requestId/details' => sub {
	my $requestId = params->{'requestId'};
	my $resolution = request->data;
	
	# Now, try finding the request id
	my $rMgmt = RDConnect::Dancer2::Common::getRequestManagementInstance();
	
	my($found,$payload) = $rMgmt->getRequestPayload($requestId);
	# Give no clue about how it worked
	if($found) {
		my $csrf_token = request->header(CSRF_HEADER());
		if ( !$csrf_token || !validate_csrf_token($csrf_token) ) {
			# We are telling the view that it should retry again
			send_error('CSRF token does not match',409);
		}
		
		# apply processing (WIP)
		$rMgmt->resolveRequest($payload,$resolution);
		
		# If we have reached this point, we are allowed to remove the request
		$rMgmt->removeRequest($requestId);
	}
	
	# Return in any case
	status 202;
	return [];
};

# This method must redirect
get '/:requestId/desist/:desistCode' => sub {
	redirect request->path().'/';
};

# This method requests the dismissal view (common)
get '/:requestId/desist/:desistCode/' => sub {
	my $requestId = params->{'requestId'};
	my $desistCode = params->{'desistCode'};
	
	# Now, try finding the request id
	my $rMgmt = RDConnect::Dancer2::Common::getRequestManagementInstance();
	
	my($found,$payload) = $rMgmt->getRequestPayload($requestId);
	
	# Give no clue about how it worked
	# Only return and set up the CSRF header when the request is found
	unless($found && $payload->{'desistCode'} eq $desistCode) {
		send_error($RDConnect::Dancer2::Common::jserr->encode({'reason' => "Request not available"}),404);
	}
	
	my $desistViewDir = $rMgmt->getDesistView($payload->{'requestType'},$payload->{'publicPayload'});
	
	if(defined($desistViewDir)) {
		send_file(File::Spec->catfile($desistViewDir,'index.html'));
	} else {
		send_error($RDConnect::Dancer2::Common::jserr->encode({'reason' => "Request not available"}),404);
	}
};

# This method validates the dismissal code
get '/:requestId/desist/:desistCode/details' => sub {
	my $requestId = params->{'requestId'};
	my $desistCode = params->{'desistCode'};
	
	# Now, try finding the request id
	my $rMgmt = RDConnect::Dancer2::Common::getRequestManagementInstance();
	
	my($found,$payload) = $rMgmt->getRequestPayload($requestId);
	
	my $publicPayload = {};
	
	# Give no clue about how it worked
	# Only set up return and the CSRF header when the request is found
	if($found && $payload->{'desistCode'} eq $desistCode) {
		$publicPayload = $payload->{'publicPayload'};
		$publicPayload->{'desistCode'} = $payload->{'desistCode'};
		header(CSRF_HEADER() => get_csrf_token());
	}
	
	return $publicPayload;
};

# This method dismisses the request
post '/:requestId/desist/:desistCode/details' => sub {
	my $requestId = params->{'requestId'};
	my $desistCode = params->{'desistCode'};
	
	# Now, try finding the request id
	my $rMgmt = RDConnect::Dancer2::Common::getRequestManagementInstance();
	
	my($found,$payload) = $rMgmt->getRequestPayload($requestId);
	# Give no clue about how it worked
	if($found && $payload->{'desistCode'} eq $desistCode) {
		my $csrf_token = request->header(CSRF_HEADER());
		if ( !$csrf_token || !validate_csrf_token($csrf_token) ) {
			# We are telling the view that it should retry again
			send_error('CSRF token does not match',409);
		}
		
		# If we have reached this point, we are allowed to remove the request
		$rMgmt->removeRequest($requestId);
	}
	
	# Return in any case
	status 202;
	return {};
};


# This method requests the dismissal view (common)
get '/:requestId/desist/:desistCode/**' => sub {
	my $requestId = params->{'requestId'};
	my $desistCode = params->{'desistCode'};
	
	# TODO; should we complain on components starting with '.'?
	# TODO; should we check whether the destination is a directory?
	my($path) = splat;
	
	# Now, try finding the request id
	my $rMgmt = RDConnect::Dancer2::Common::getRequestManagementInstance();
	
	my($found,$payload) = $rMgmt->getRequestPayload($requestId);
	
	# Give no clue about how it worked
	# Only return and set up the CSRF header when the request is found
	unless($found && $payload->{'desistCode'} eq $desistCode) {
		send_error($RDConnect::Dancer2::Common::jserr->encode({'reason' => "Request not available"}),404);
	}
	
	my $desistViewDir = $rMgmt->getDesistView($payload->{'requestType'},$payload->{'publicPayload'});
	
	if(defined($desistViewDir)) {
		my $sendPath = File::Spec->catfile($desistViewDir,@{$path});
		if(! -r $sendPath && scalar(@{$path}) > 0 && $path->[0] eq 'common') {
			$sendPath = File::Spec->catfile(@{$path});
		}
		send_file($sendPath);
	} else {
		send_error($RDConnect::Dancer2::Common::jserr->encode({'reason' => "Request not available"}),404);
	}
};

# This method must redirect or return the view, based on the kind of operation
# There are "special" request ids, for fixed operations, like requesting a password reset
get '/:requestId/**' => sub {
	my $requestId = params->{'requestId'};
	
	# TODO; should we complain on components starting with '.'?
	# TODO; should we check whether the destination is a directory?
	my($path) = splat;
	
	# Now, try finding the request id
	my $rMgmt = RDConnect::Dancer2::Common::getRequestManagementInstance();
	
	my($found,$payload) = $rMgmt->getRequestPayload($requestId);
	
	unless($found) {
		send_error($RDConnect::Dancer2::Common::jserr->encode({'reason' => "Request not available"}),404);
	}
	
	my $viewDir = $rMgmt->getRequestView($payload->{'requestType'},$payload->{'publicPayload'});
	
	if(defined($viewDir)) {
		my $sendPath = File::Spec->catfile($viewDir,@{$path});
		if(! -r $sendPath && scalar(@{$path}) > 0 && $path->[0] eq 'common') {
			$sendPath = File::Spec->catfile(@{$path});
		}
		send_file($sendPath);
	} else {
		send_error($RDConnect::Dancer2::Common::jserr->encode({'reason' => "Request not available"}),404);
	}
};


#hook before => sub {
#	# ..
#	if ( request->is_post() ) {
#		my $csrf_token = request->header(CSRF_HEADER());
#		if ( !$csrf_token || !validate_csrf_token($csrf_token) ) {
#			  redirect '/?error=invalid_csrf_token';
#		}
#		# ...
#	}
#};
#
## This rule 
#hook after => sub {
#	if(request->is_get()) {
#		response->push_header(CSRF_HEADER() => get_csrf_token());
#	}
#};

1;

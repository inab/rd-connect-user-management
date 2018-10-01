#!/usr/bin/perl
# RD-Connect User Management REST API
# José María Fernández (jose.m.fernandez@bsc.es)

use strict;
use warnings 'all';

use FindBin;
use File::Spec;
use local::lib File::Spec->catfile($FindBin::Bin,'.plEnv');

use lib File::Spec->catfile($FindBin::Bin,'libs');

use RDConnect::UserManagement::DancerCommon;
use RDConnect::UserManagement::API;
use RDConnect::UserManagement::Requests;

use Plack::Builder;
builder {
	# Order does matter!
	enable 'CrossOrigin', origins => '*', headers => '*';
	# When this module is enabled, it introduces a double encoding issue.
	#enable 'Deflater', content_type => ['text/plain','text/css','text/html','text/javascript','application/javascript','application/json'];
	mount '/requests/'    => RDConnect::UserManagement::Requests->to_app;
	mount '/'    => RDConnect::UserManagement::API->to_app;
};

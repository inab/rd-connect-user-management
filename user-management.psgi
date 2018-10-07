#!/usr/bin/perl
# RD-Connect User Management REST API
# José María Fernández (jose.m.fernandez@bsc.es)

use strict;
use warnings 'all';

use FindBin;
use File::Spec;
use local::lib File::Spec->catfile($FindBin::Bin,'.plEnv');

use lib File::Spec->catfile($FindBin::Bin,'libs');

use RDConnect::Dancer2::UserManagementAPI;
use RDConnect::Dancer2::RequestsAPI;

use Plack::Builder;
builder {
	# Order does matter!
	enable 'CrossOrigin', origins => '*', headers => '*';
	# When this module is enabled, it introduces a double encoding issue.
	#enable 'Deflater', content_type => ['text/plain','text/css','text/html','text/javascript','application/javascript','application/json'];
	mount '/requests/'    => RDConnect::Dancer2::RequestsAPI->to_app;
	mount '/'    => RDConnect::Dancer2::UserManagementAPI->to_app;
};

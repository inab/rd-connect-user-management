#!/usr/bin/perl
# RD-Connect User Management REST API
# José María Fernández (jmfernandez@cnio.es)

use strict;
use warnings 'all';

# For some reason Apache SetEnv directives dont propagate
# correctly to the dispatchers, so forcing PSGI and env here
# is safer.
BEGIN {
	$ENV{DANCER_APPHANDLER} = 'PSGI';
}

use Dancer2;
use Dancer2::FileUtils;
use File::Spec;
use FindBin;

set apphandler => 'PSGI';
set environment => 'production';

# Removing the extension
my $psgi = Dancer2::FileUtils::path($FindBin::Script);
my($volume,$directories,$file) = File::Spec->splitpath($psgi);

my $rdot = rindex($file,'.');
if($rdot != -1) {
	$file = substr($file,0,$rdot);
	
	$psgi = File::Spec->catpath($volume,$directories,$file);
}
# Adding the new extension
$psgi .= '.psgi';

die "Unable to find RD-Connect User Management REST API script: $psgi" unless(-r $psgi);

# This is for plain CGIs
use Plack::Runner;
Plack::Runner->run($psgi);
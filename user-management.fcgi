#!/usr/bin/perl
# RD-Connect User Management REST API
# José María Fernández (jose.m.fernandez@bsc.es)

use strict;
use warnings 'all';

use FindBin;
use File::Spec;
use local::lib File::Spec->catfile($FindBin::Bin,'.plEnv');

use Dancer2::FileUtils;
use File::Spec;
use FindBin;

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

# This is for FastCGI
use Plack::Handler::FCGI;

my $app = do($psgi);
die "Unable to parse RD-Connect User Management REST API script: $@" if $@;
my $server = Plack::Handler::FCGI->new(nproc => 5, detach => 1);

$server->run($app);

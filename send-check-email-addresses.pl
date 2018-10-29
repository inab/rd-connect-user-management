#!/usr/bin/perl
# RD-Connect User Management Scripts
# José María Fernández (jose.m.fernandez@bsc.es)

use warnings "all";
use strict;

use FindBin;
use File::Spec;
use local::lib File::Spec->catfile($FindBin::Bin,'.plEnv');

use Carp;
use Config::IniFiles;

use lib File::Spec->catfile($FindBin::Bin,'libs');
use RDConnect::UserManagement;
use RDConnect::TemplateManagement;
use RDConnect::MetaUserManagement;

use constant SECTION	=>	'main';

if(scalar(@ARGV)>=2) {
	my $configFile = shift(@ARGV);
	my @users = @ARGV;
	
	# LDAP configuration
	my $cfg = Config::IniFiles->new( -file => $configFile);
	my $uMgmt = RDConnect::UserManagement->new($cfg);
	my $tMgmt = RDConnect::TemplateManagement->new($uMgmt);
	my $mMgmt = RDConnect::MetaUserManagement->new($tMgmt);
	
	foreach my $username (@users) {
		# Don't send the e-mail to disabled accounts
		print "* Preparing and sending e-mail(s) to $username\n";
		$mMgmt->sendUsernameEMailRequests($username);
	}
} else {
	die <<EOF ;
Usage:	$0 {IniFile} {username}+
EOF
}

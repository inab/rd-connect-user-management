#!/usr/bin/perl

use warnings "all";
use strict;

use FindBin;
use File::Spec;
use local::lib File::Spec->catfile($FindBin::Bin,'.plEnv');

use Carp;
use Config::IniFiles;
use Email::Address;
use Text::Unidecode qw();

use lib File::Spec->catfile($FindBin::Bin,'libs');
use RDConnect::UserManagement;
use RDConnect::MetaUserManagement;

use constant SECTION	=>	'main';

my $paramPassword;
if(scalar(@ARGV)>0 && $ARGV[0] eq '-p') {
	shift(@ARGV);
	$paramPassword = 1;
}

if((!defined($paramPassword) && scalar(@ARGV)>=2) || (defined($paramPassword) && scalar(@ARGV) == 3)) {
	my $configFile = shift(@ARGV);
	
	my $cfg = Config::IniFiles->new( -file => $configFile);
	
	my $password;
	my @usernames = ();
	if(defined($paramPassword)) {
		push(@usernames,$ARGV[0]);
		$password = $ARGV[1];
	} else {
		@usernames = @ARGV;
	}
	
	# LDAP configuration
	my $uMgmt = RDConnect::UserManagement->new($cfg);
	
	# Read the users
	foreach my $username (@usernames) {
		my $pass;
		if(defined($password)) {
			$pass = $password;
		}
		
		my $retval = RDConnect::MetaUserManagement::ResetUserPassword($uMgmt,$username,$pass);
		
		if(defined($retval)) {
			Carp::carp($retval->{'reason'}.'. Trace: '.(ref($retval->{'trace'})?join("\n",@{$retval->{'trace'}}):$retval->{'trace'}));
		} else {
			print "User $username password was reset\n";
		}
	}
} else {
	die <<EOF ;
Usage:	$0 {IniFile} {username or user e-mail}+
	$0 -p {IniFile} {username or user e-mail} {new password}
EOF
}

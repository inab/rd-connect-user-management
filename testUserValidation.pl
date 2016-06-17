#!/usr/bin/perl

use warnings "all";
use strict;

use FindBin;
use lib $FindBin::Bin . '/libs';
use RDConnect::UserManagement;

my $userVal = RDConnect::UserManagement::getCASUserValidator();

my @errors = $userVal->validate({
	"givenName" => "José María",
      "surname" => "Fernández González",
      "username" => "j.m.fernandez",
        "hashedPasswd64" => undef,
          "email" =>  'perico+gmail@nobody.org'
});

if(scalar(@errors) > 0) {
	print STDERR "Errors: \n";
	foreach my $error (@errors) {
		print STDERR "\tPath: ".$error->{'path'}.' . Message: '.$error->{'message'},"\n";
	}
}

@errors = $userVal->validate({
	"givenName" => "José María",
#      "surname" => "Fernández González",
#      "username" => "j.m.fernandez",
#        "hashedPasswd64" => undef,
          "email" =>  'perico+gmail@nobody.org'
});

if(scalar(@errors) > 0) {
	print STDERR "Errors: \n";
	foreach my $error (@errors) {
		print STDERR "\tPath: ".$error->{'path'}.' . Message: '.$error->{'message'},"\n";
	}
}

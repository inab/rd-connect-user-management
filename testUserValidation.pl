#!/usr/bin/perl
# RD-Connect User Management Scripts
# José María Fernández (jose.m.fernandez@bsc.es)

use warnings "all";
use strict;

use FindBin;
use File::Spec;
use local::lib File::Spec->catfile($FindBin::Bin,'.plEnv');

use File::Path;

use lib File::Spec->catfile($FindBin::Bin,'libs');
use RDConnect::UserManagement;

my $userVal = RDConnect::UserManagement::getCASUserValidator();

if(scalar(@ARGV)>0) {
	my $j = RDConnect::UserManagement::getJSONHandler();
	foreach my $file (@ARGV) {
		print STDERR "Validating $file\n";
		
		if(open(my $JH,'<:encoding(utf-8)',$file)) {
			my $data;
			{
				local $/;
				my $lines=<$JH>;
				$data = $j->decode($lines);
			}
			close($JH);
			
			my @errors = $userVal->validate($data);
			
			if(scalar(@errors) > 0) {
				print STDERR "\* Errors on $file: \n";
				foreach my $error (@errors) {
					print STDERR "\t  Path: ".$error->{'path'}.' . Message: '.$error->{'message'},"\n";
				}
			} else {
				print STDERR "\t* No errors on $file\n";
			}
		} else {
			print STDERR "ERROR: Unable to open file $file. Reason: $!\n";
		}
	}
} else {
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
}

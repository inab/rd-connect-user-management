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
use File::Path;
use File::Spec;
use JSON::MaybeXS ();
use Scalar::Util;

use lib File::Spec->catfile($FindBin::Bin,'libs');
use RDConnect::UserManagement;
use RDConnect::TemplateManagement;

if(scalar(@ARGV)==3) {
	my $configFile = shift(@ARGV);
	my $ldapDomain = shift(@ARGV);
	my $destdir = shift(@ARGV);

	my $cfg = Config::IniFiles->new( -file => $configFile);

	# LDAP configuration
	my $uMgmt = RDConnect::UserManagement->new($cfg);
	my $tMgmt = RDConnect::TemplateManagement->new($uMgmt);
	my $j = JSON::MaybeXS->new('convert_blessed' => 1,'utf8' => 0,'pretty' => 1);
	
	print "* Reading templates for domain $ldapDomain\n";
	my($mailTemplate,$mailTemplateTitle,@attachments) = $tMgmt->fetchEmailTemplate($ldapDomain);
	
	if(Scalar::Util::blessed($mailTemplate) && $mailTemplate->isa('RDConnect::TemplateManagement::Error')) {
		my $j = JSON::MaybeXS->new('allow_blessed' => 1,'convert_blessed' => 1,'utf8' => 0,'pretty' => 1);
		Carp::croak($j->encode($mailTemplate));
	} else {
		# Assure the directory existence
		File::Path::make_path($destdir);
		
		# Now, save the templates in the destination directory
		print "\t- Title: ",$mailTemplateTitle,"\n";
		foreach my $mTemplate ($mailTemplate,@attachments) {
			my $mailTPath = File::Spec->catfile($destdir,$mTemplate->{'cn'});
			print "\t- Saving $mailTPath\n";
			if(open(my $MT,'>',$mailTPath)) {
				print $MT ${$mTemplate->{'content'}};
				close($MT);
			} else {
				Carp::croak("Unable to save ".$mTemplate->{'cn'}." . Reason: ".$!);
			}
		}
	}
} else {
	die <<EOF ;
Usage:	$0 {IniFile} {domain id} {destination directory}
EOF
}

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

if(scalar(@ARGV)>=4) {
	my $configFile = shift(@ARGV);
	my $ldapDomain = shift(@ARGV);
	my $titleTemplate = shift(@ARGV);
	my $messageTemplateFile = shift(@ARGV);
	
	my $cfg = Config::IniFiles->new( -file => $configFile);

	# LDAP configuration
	my $uMgmt = RDConnect::UserManagement->new($cfg);
	my $tMgmt = RDConnect::TemplateManagement->new($uMgmt);
	my $j = JSON::MaybeXS->new('convert_blessed' => 1,'utf8' => 0,'pretty' => 1);
	
	print "* Setting templates for domain $ldapDomain\n";
	my($success) = $tMgmt->setEmailTemplate($ldapDomain,$titleTemplate,$messageTemplateFile,@ARGV);
	
	if(Scalar::Util::blessed($success) && $success->isa('RDConnect::TemplateManagement::Error')) {
		Carp::carp("ERROR: ".$success->{'reason'});
		if(exists($success->{'trace'})) {
			my $trace = (ref($success->{'trace'}) eq 'ARRAY') ? $success->{'trace'} : [$success->{'trace'}];
			Carp::carp("TRACE:");
			foreach my $retval (@{$trace}) {
				Carp::carp($retval);
			}
		}
		exit 1;
	} else {
		print "Domain $ldapDomain has its templates updated\n";
	}
} else {
	die <<EOF ;
Usage:	$0 {IniFile} {domain id} {Title Template} {Message Template} {Attachments}*
EOF
}

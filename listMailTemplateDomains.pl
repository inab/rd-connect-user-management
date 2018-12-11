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
use JSON::MaybeXS ();

use lib File::Spec->catfile($FindBin::Bin,'libs');
use RDConnect::UserManagement;
use RDConnect::TemplateManagement;
use RDConnect::MetaUserManagement;

if(scalar(@ARGV)>=1) {
	my $configFile = shift(@ARGV);

	my $cfg = Config::IniFiles->new( -file => $configFile);

	# LDAP configuration
	my $uMgmt = RDConnect::UserManagement->new($cfg);
	my $tMgmt = RDConnect::TemplateManagement->new($uMgmt);
	my $p_mtDomains = $tMgmt->getMailTemplatesDomains();
	my $j = JSON::MaybeXS->new('convert_blessed' => 1,'utf8' => 0,'pretty' => 1);
	
	print "* List of mail template domains\n";
	foreach my $p_domain (@{$p_mtDomains}) {
		print "\t- ",$p_domain->{'apiKey'}," (domain ",$p_domain->{'ldapDomain'},", tokens ",join(", ",@{$p_domain->{'tokens'}}),"): ",$p_domain->{'desc'},"\n";
		
		my $ldapDomain = $p_domain->{'ldapDomain'};
		my($success,$payload) = $uMgmt->listJSONDocumentsFromDomain($ldapDomain);
		
		unless($success) {
			# Last attempt, trying to materialize the template (if it is possible)
			$tMgmt->fetchEmailTemplate($ldapDomain);
					
			# Last attempt, trying to materialize the template (if it is possible)
			($success,$payload) = $uMgmt->listJSONDocumentsFromDomain($ldapDomain);
		}
		
		if($success) {
			print $j->encode($payload);
		} else {
			foreach my $retval (@{$payload}) {
				Carp::carp($retval);
			}
		}
	}

} else {
	die <<EOF ;
Usage:	$0 {IniFile}
EOF
}

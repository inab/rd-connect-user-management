#!/usr/bin/perl
# RD-Connect User Management REST API
# José María Fernández (jose.m.fernandez@bsc.es)

use strict;
use warnings 'all';

use FindBin;
use File::Spec;

use JSON::MaybeXS qw();

package RDConnect::Dancer2::Common;

use constant API_CONFIG_DIRNAME	=>	'configs';
use constant API_CONFIG_FILENAME	=>	'user-management.ini';
use constant API_CONFIG_FILE	=>	File::Spec->catfile($FindBin::Bin,API_CONFIG_DIRNAME,API_CONFIG_FILENAME);

{
	use Config::IniFiles;
	
	my $cfg = undef;
	
	sub getRDConnectConfig() {
		unless(defined($cfg)) {
			# Now, let's read all the parameters
			$cfg = Config::IniFiles->new( -file => API_CONFIG_FILE);
		}
		
		return $cfg;
	}
	
	use constant UMGMT_API_SECTION	=>	'rdconnect-usermanagement-api';
	use constant DEFAULT_RDCONNECT_CAS_URL	=>	"https://rdconnectcas.rd-connect.eu:9443/cas";
	
	sub getCASurl() {
		my $cfg = getRDConnectConfig();
		
		return $cfg->val(UMGMT_API_SECTION,'cas_url',DEFAULT_RDCONNECT_CAS_URL);
	}
	
	sub getAdminGroups() {
		my $cfg = getRDConnectConfig();
		
		my $retval = ['cn=admin,ou=groups,dc=rd-connect,dc=eu'];
		
		if($cfg->exists(UMGMT_API_SECTION,'admin_group')) {
			my @adminGroups = $cfg->val(UMGMT_API_SECTION,'admin_group');
			$retval = \@adminGroups;
		}
		
		return $retval;
	}
	
	use constant DEFAULT_RDCONNECT_GROUP_CREATOR	=>	'PI';
	
	sub getGroupCreator() {
		my $cfg = getRDConnectConfig();
		
		return $cfg->val(UMGMT_API_SECTION,'group_creator',DEFAULT_RDCONNECT_GROUP_CREATOR);
	}
	
	use RDConnect::UserManagement;
	
	my $uMgmt = undef;
	
	sub getUserManagementInstance() {
		unless(defined($cfg) && defined($uMgmt)) {
			# Now, let's read all the parameters
			my $cfg = getRDConnectConfig();
			
			# LDAP configuration
			$uMgmt = RDConnect::UserManagement->new($cfg);
		}
		
		return $uMgmt;
	}
	
	use RDConnect::TemplateManagement;
	
	my $tMgmt = undef;
	
	sub getTemplateManagementInstance() {
		unless(defined($uMgmt) && defined($tMgmt)) {
			my $uMgmt = getUserManagementInstance();
			
			$tMgmt = RDConnect::TemplateManagement->new($uMgmt);
		}
		
		return $tMgmt;
	}
	
	use RDConnect::RequestManagement;
	
	my $rMgmt = undef;
	
	sub getMetaUserManagementInstance();
	
	sub getRequestManagementInstance() {
		unless(defined($tMgmt) && defined($rMgmt)) {
			my $tMgmt = getTemplateManagementInstance();
			
			$rMgmt = RDConnect::RequestManagement->new($tMgmt);
			
			# Now, this step assures the request management has 
			# initialized its ties to the meta user management
			getMetaUserManagementInstance();
		}
		
		return $rMgmt;
	}
	
	use RDConnect::MetaUserManagement;
	
	my $mMgmt = undef;
	
	sub getMetaUserManagementInstance() {
		unless(defined($rMgmt) && defined($mMgmt)) {
			my $rMgmt = getRequestManagementInstance();
			
			$mMgmt = RDConnect::MetaUserManagement->new($rMgmt);
		}
		
		return $mMgmt;
	}
	
	sub getMailManagementInstance($\%;\@) {
		my($mailTemplate,$p_keyvals,$p_attachmentFiles) = @_;
		
		$p_attachmentFiles = []  unless(defined($p_attachmentFiles));
		
		# Mail configuration parameters
		return $mMgmt->getMailManagementInstance($mailTemplate,$p_keyvals,$p_attachmentFiles);
	}
}

our $jserr = JSON::MaybeXS->new({'allow_blessed' => 1, 'convert_blessed' => 1});

1;

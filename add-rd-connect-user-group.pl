#!/usr/bin/perl
# RD-Connect User Management Scripts
# José María Fernández (jose.m.fernandez@bsc.es)

use warnings "all";
use strict;

use FindBin;
use File::Spec;
use local::lib File::Spec->catfile($FindBin::Bin,'.plEnv');

use Carp 'verbose';
use Config::IniFiles;

use lib File::Spec->catfile($FindBin::Bin,'libs');
use RDConnect::UserManagement;

use constant SECTION	=>	'main';

sub addUserLikeToGroups($$$) {
	my($uMgmt,$origUserUID,$groupCN) = @_;
	
	my @origUserUIDs = split(/,/,$origUserUID);
	
	my @groupCNs = split(/,/,$groupCN);
	
	my @userUIDs = ();
	
	my $success = 1;
	my $p_users = undef;
	foreach my $userUID (@origUserUIDs) {
		my $selector = substr($userUID,0,1);
		
		if($selector eq '@') {
			$success = 1;
			# UserUIDs are in a file
			my $tabUsersFilename = substr($userUID,1);
			if(open(my $T,'<:encoding(UTF-8)',$tabUsersFilename)) {
				while(my $line=<$T>) {
					next  if(substr($line,0,1) eq '#');
					
					chomp($line);
					push(@userUIDs,$line);
				}
				close($T);
			} else {
				Carp::croak("ERROR: Unable to open users filename $tabUsersFilename. Reason: $!");
			}
		} elsif($selector eq '+') {
			my $thisGroupCN = substr($userUID,1);
			($success,$p_users) = $uMgmt->getGroupMembers($thisGroupCN);
		} elsif($selector eq '&') {
			my $thisPeopleOU = substr($userUID,1);
			($success,$p_users) = $uMgmt->listPeopleOUUsers($thisPeopleOU);
		} elsif($userUID eq '*') {
			($success,$p_users) = $uMgmt->listEnabledUsers();
		} else {
			# There is no selector
			$success = 1;
			push(@userUIDs,$userUID);
		}
		
		last  unless($success);
		
		push(@userUIDs,@{$p_users})  if(defined($p_users));
	}
	
	($success,$p_users) = $uMgmt->addMemberToGroup(\@userUIDs,\@groupCNs)  if($success);
		
	unless($success) {
		foreach my $retval (@{$p_users}) {
			Carp::carp($retval);
		}
		Carp::croak("ERROR: Unable to associate user $origUserUID to group(s) $groupCN");
	}
}

sub processUserGroupsFile($$) {
	my($uMgmt,$userGroupsFile) = @_;
	
	if(open(my $UG,'<:encoding(UTF-8)',$userGroupsFile)) {
		while(my $line=<$UG>) {
			# Skipping comments
			next  if(substr($line,0,1) eq '#');
			
			$line =~ s/[\n\r]+$//s;
			my($userUID,$groupCN,$altUserUID,$altGroupCN,$junk) = split(/\t/,$line,5);
			
			if(defined($altGroupCN) && length($altGroupCN) > 0) {
				$userUID = $altUserUID;
				
				my $firstComma = index($altGroupCN,',');
				$groupCN = ($firstComma == -1) ? $altGroupCN : substr($altGroupCN,$firstComma+1);
			}
			
			addUserLikeToGroups($uMgmt,$userUID,$groupCN);
			
			print "$userUID => $groupCN\n";
		}
		
		close($UG);
	} else {
		Carp::croak("Unable to read file $userGroupsFile");
	}
}

my $isInlineFlag = undef;
if(scalar(@ARGV)>0 && $ARGV[0] eq '-i') {
	shift(@ARGV);
	$isInlineFlag = 1;
}

my $minParams = $isInlineFlag ? 3 : 2;

if(scalar(@ARGV)>=$minParams) {
	my $configFile = shift(@ARGV);
	
	# Now, let's read all the parameters
	my $cfg = Config::IniFiles->new( -file => $configFile);
	
	# LDAP configuration
	my $uMgmt = RDConnect::UserManagement->new($cfg);
	
	if($isInlineFlag) {
		my($userUID,$groupCN) = @ARGV;
		addUserLikeToGroups($uMgmt,$userUID,$groupCN);
	} else {
		foreach my $userGroupsFile (@ARGV) {
			processUserGroupsFile($uMgmt,$userGroupsFile);
		}
	}
} else {
	print STDERR<<EOF;
Usage:
	$0 {IniFile} {Tabular file with user <-> group correspondence}+
	or
	$0 -i {IniFile} {userUID (separated by commas)} {groupCN (separated by commas)}
	
	where each userUID can have next format:
	\@filename (a filename with a list of user UIDs)
	+groupCN (the members of the group identified by this cn)
	&peopleOU (the members of the organizational unit identified by this ou)
	* (all the enabled users)
EOF
	exit 1;
}

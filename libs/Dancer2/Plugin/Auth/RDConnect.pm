# RD-Connect User Management Scripts
# José María Fernández (jose.m.fernandez@bsc.es)

use 5.008001;
use strict;
use warnings;


package Dancer2::Plugin::Auth::RDConnect;

=encoding utf8
=head1 NAME

Dancer2::Plugin::Auth::RDConnect - Authorization rules for RD-Connect user management

=cut

use warnings;
use strict;

use Carp;
use Dancer2::Plugin;
use HTTP::Headers;
use Scalar::Util 'blessed';

our $VERSION;

use constant InvalidConfig => "Invalid or missing configuration: ";
use constant NoSession => "Unavailable session";
use constant ExpiredSession => "Expired session";
use constant CorruptedSession => "Corrupted session";
use constant CasError => "Unable to auth with CAS backend: ";
use constant FailedToAuthenticate => "Failed to authenticate. Destroying session.";

my $settings;
my %dispatch = (
	admin => \&_auth_admin,
	user => \&_auth_user,
	PI => \&_auth_pi,
	owner => \&_auth_owner,
);

register 'rdconnect_auth' => sub {
	my ( $dsl, $condition, @args ) = @_;
	
	my $builder = $dispatch{$condition};
	
	if ( ref $builder eq 'CODE' ) {
		return $builder->( $dsl, @args );
	} else {
		croak "Unknown authorization condition '$condition'";
	}
};

sub extend {
	my ( $class, @args ) = @_;
	unless ( @args % 2 == 0 ) {
		croak "arguments to $class\->extend must be key/value pairs";
	}
	%dispatch = ( %dispatch, @args );
}

sub _default_conf {
	return (
		# This key is shared
		cas_user_map	=>	'cas_user',
		username_attribute	=>	'username',
		groups_attribute	=>	'memberOf',
		userCategory_attribute	=>	'userCategory',
		rdconnect_group_creator	=>	'PI',
		rdconnect_admin_groups	=>	['cn=admin,ou=groups,dc=rd-connect,dc=eu'],
		# This attribute must hold an instance of RDConnect::UserManagement
		uMgmt	=>	undef
	);
}

use constant SESSION_HEADER	=>	'X-RDConnect-UserManagement-Session';

sub _auth_admin {
	my ( $dsl, $coderef ) = @_;
	
	$settings ||= { _default_conf(), %{ plugin_setting() } };
	#use Data::Dumper;
	#print STDERR Dumper($settings),"\n";
	
	return sub {
		my $app = $dsl->app;
		my $request = $app->request;
		
		# The request should have stored in its variables the attributes
		my $username = '(unknown)';
		if(exists($request->vars->{$settings->{cas_user_map}})) {
			my $user_attributes = $request->vars->{$settings->{cas_user_map}};
			
			# We need to know the user
			if(exists($user_attributes->{$settings->{username_attribute}})) {
				$username = $user_attributes->{$settings->{username_attribute}};
				
				# And its groups (if any)
				my $p_groups = [];
				if(exists($user_attributes->{$settings->{groups_attribute}})) {
					$p_groups = $user_attributes->{$settings->{groups_attribute}};
				}
				
				my $p_admin_groups = $settings->{rdconnect_admin_groups};
				
				foreach my $user_group (@{$p_groups}) {
					my $lc_user_group = lc($user_group);
					foreach my $admin_group (@{$p_admin_groups}) {
						# Jump to the code
						goto $coderef  if($lc_user_group eq lc($admin_group));
					}
				}
			}

		}
		my $message = "Access denied admin role: user $username";
		$app->log( error => $message);
		$app->send_error($message, 403);
	};
}

sub _auth_user {
	my ( $dsl, $coderef ) = @_;
	
	$settings ||= { _default_conf(), %{ plugin_setting() } };
	#use Data::Dumper;
	#print STDERR Dumper($settings),"\n";
	
	return sub {
		my $app = $dsl->app;
		my $request = $app->request;
		my $uMgmt = $settings->{uMgmt};
		
		# The request should have stored in its variables the attributes
		my $username = '(unknown)';
		if(exists($request->vars->{$settings->{cas_user_map}})) {
			my $user_attributes = $request->vars->{$settings->{cas_user_map}};
			
			# We need to know the user
			if(exists($user_attributes->{$settings->{username_attribute}})) {
				$username = $user_attributes->{$settings->{username_attribute}};
				
				# Jump to the code if the requested user matches with the logged-in
				goto $coderef  if(exists($request->params->{'user_id'}) && lc($request->params->{'user_id'}) eq lc($username));
				
				# And its groups (if any)
				my $p_groups = [];
				if(exists($user_attributes->{$settings->{groups_attribute}})) {
					$p_groups = $user_attributes->{$settings->{groups_attribute}};
				}
				
				my $p_admin_groups = $settings->{rdconnect_admin_groups};
				
				foreach my $user_group (@{$p_groups}) {
					my $lc_user_group = lc($user_group);
					foreach my $admin_group (@{$p_admin_groups}) {
						# Jump to the code
						goto $coderef  if($lc_user_group eq lc($admin_group));
					}
				}
			}

		}
		my $message = "Access denied admin or user role: user $username";
		$app->log( error => $message);
		$app->send_error($message,403);
	};
}

sub _auth_pi {
	my ( $dsl, $coderef ) = @_;
	
	$settings ||= { _default_conf(), %{ plugin_setting() } };
	#use Data::Dumper;
	#print STDERR Dumper($settings),"\n";
	
	return sub {
		my $app = $dsl->app;
		my $request = $app->request;
		my $uMgmt = $settings->{uMgmt};
		
		# The request should have stored in its variables the attributes
		my $username = '(unknown)';
		if(exists($request->vars->{$settings->{cas_user_map}})) {
			my $user_attributes = $request->vars->{$settings->{cas_user_map}};
			
			# We need to know the user (in order to blame him/her)
			if(exists($user_attributes->{$settings->{username_attribute}})) {
				$username = $user_attributes->{$settings->{username_attribute}};
				
				# Jump to the code if the requested user is a PI
				goto $coderef  if(exists($user_attributes->{$settings->{userCategory_attribute}}) && $user_attributes->{$settings->{userCategory_attribute}} eq $settings->{rdconnect_group_creator});
				
				# And its groups (if any)
				my $p_groups = [];
				if(exists($user_attributes->{$settings->{groups_attribute}})) {
					$p_groups = $user_attributes->{$settings->{groups_attribute}};
				}
				
				my $p_admin_groups = $settings->{rdconnect_admin_groups};
				
				foreach my $user_group (@{$p_groups}) {
					my $lc_user_group = lc($user_group);
					foreach my $admin_group (@{$p_admin_groups}) {
						# Jump to the code
						goto $coderef  if($lc_user_group eq lc($admin_group));
					}
				}
			}

		}
		my $message = "Access denied admin or group creator role: user $username";
		$app->log( error => $message);
		$app->send_error($message,403);
	};
}

sub _auth_owner {
	my ( $dsl, $coderef ) = @_;
	
	$settings ||= { _default_conf(), %{ plugin_setting() } };
	#use Data::Dumper;
	#print STDERR Dumper($settings),"\n";
	
	return sub {
		my $app = $dsl->app;
		my $request = $app->request;
		my $uMgmt = $settings->{uMgmt};
		
		# The request should have stored in its variables the attributes
		my $username = '(unknown)';
		if(exists($request->vars->{$settings->{cas_user_map}})) {
			my $user_attributes = $request->vars->{$settings->{cas_user_map}};
			
			# We need to know the user
			if(exists($user_attributes->{$settings->{username_attribute}})) {
				$username = $user_attributes->{$settings->{username_attribute}};
				
				# We need a valid group id
				if(defined($uMgmt) && exists($request->params->{group_id})) {
					my($successUser,$ldapUser) = $uMgmt->getUser($username);
					
					if($successUser) {
						my($successGroup,$ldapGroup) = $uMgmt->getGroup($request->params->{group_id});
						
						if($successGroup) {
							if($ldapGroup->exists('owner')) {
								my $p_owners = $ldapGroup->get_value('owner', asref => 1);
								my $userDN = lc($ldapUser->dn());
								
								foreach my $owner (@{$p_owners}) {
									# Jump to the code if the logged-in user is an owner
									goto $coderef  if(lc($owner) eq $userDN);
								}
							}
							
							# And its groups (if any)
							my $p_groups = [];
							if(exists($user_attributes->{$settings->{groups_attribute}})) {
								$p_groups = $user_attributes->{$settings->{groups_attribute}};
							}
							
							my $p_admin_groups = $settings->{rdconnect_admin_groups};
							
							foreach my $user_group (@{$p_groups}) {
								my $lc_user_group = lc($user_group);
								foreach my $admin_group (@{$p_admin_groups}) {
									# Jump to the code
									goto $coderef  if($lc_user_group eq lc($admin_group));
								}
							}
						}
					}
				}
			}

		}
		my $message = "Access denied admin or group owner role: user $username";
		$app->log( error => $message);
		$app->send_error($message,403);
	};
}


register_plugin for_versions => [2];

1; # End of Dancer2::Plugin::Auth::RDConnect

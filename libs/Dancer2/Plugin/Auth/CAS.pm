# RD-Connect User Management Scripts
# José María Fernández (jose.m.fernandez@bsc.es)

use 5.008001;
use strict;
use warnings;

# With this patch we support CAS 3.0 protocol
use Authen::CAS::Client;
package Authen::CAS::Client;

sub p3_service_validate {
  my ( $self, $service, $ticket, %args ) = @_;
  print STDERR "SER: $service TICK: $ticket\n";
  return $self->_v20_validate( '/p3/serviceValidate', $service, $ticket, %args );
}
 
sub p3_proxy_validate {
  my ( $self, $service, $ticket, %args ) = @_;
  return $self->_v20_validate( '/p3/proxyValidate', $service, $ticket, %args );
}

package Dancer2::Plugin::Auth::CAS;

=encoding utf8
=head1 NAME

Dancer2::Plugin::Auth::CAS - CAS sso authentication for Dancer2

=cut

use warnings;
use strict;

use Carp;
use Dancer2::Plugin;
use HTTP::Headers;
use Scalar::Util 'blessed';
use Authen::CAS::External;

our $VERSION;

use constant InvalidConfig => "Invalid or missing configuration: ";
use constant NoSession => "Unavailable session";
use constant ExpiredSession => "Expired session";
use constant CorruptedSession => "Corrupted session";
use constant CasError => "Unable to auth with CAS backend: ";
use constant FailedToAuthenticate => "Failed to authenticate. Destroying session.";

my $settings;
my %dispatch = (
	login => \&_auth_cas,
	logout => \&_deauth_cas,
	pre_auth => \&_pre_auth_cas
);

register 'auth_cas' => sub {
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
		cas_user_map	=>	'cas_user',
		#cas_transient_params	=>	'cas_transient_params',
		cas_denied_path	=>	'denied',
		ssl_verify_hostname	=>	1,
		cas_attr_map	=>	{},
		cas_attr_as_array_map => {}
	);
}

use constant SESSION_HEADER	=>	'X-RDConnect-UserManagement-Session';

sub _deauth_cas {
	my ( $dsl, $coderef ) = @_;
	
	$settings ||= { _default_conf(), %{ plugin_setting() } };
	#use Data::Dumper;
	#print STDERR Dumper($settings),"\n";
	
	return sub {
		my $app = $dsl->app;
		my $request = $app->request;
		my $sessionId = $request->header(SESSION_HEADER);
		if(defined($sessionId)) {
			my $sessionFactory = $app->session_engine;
			$sessionFactory->destroy($sessionId);
		}
		
		# Jump to the code
		goto $coderef;
	};
}

sub _auth_cas {
	my ( $dsl, $coderef ) = @_;
	
	$settings ||= { _default_conf(), %{ plugin_setting() } };
	#use Data::Dumper;
	#print STDERR Dumper($settings),"\n";
	
	return sub {
		my $app = $dsl->app;
		my $request = $app->request;
		
		my $cas_url = $settings->{cas_url} || $app->send_error(InvalidConfig . "cas_url is unset" );
		my $cas_version = $settings->{cas_version} ||  $app->send_error(InvalidConfig . "cas_version is unset");
		my $cas_user_map = $settings->{cas_user_map};
		
		my $ssl_verify_hostname = $settings->{ssl_verify_hostname};
		$ENV{"PERL_LWP_SSL_VERIFY_HOSTNAME"} = $ssl_verify_hostname;

		# check supported versions
		unless( grep(/$cas_version/, qw( 3.0 2.0 1.0 )) ) {
			$app->send_error(InvalidConfig . "cas_version '$cas_version' not supported");
		}
		
		my $mapping = $settings->{cas_attr_map};
		my $asArray = $settings->{cas_attr_as_array_map};
		my $params = $request->params;
		
		my $sessionFactory = $app->session_engine;
		my $sessionId = $request->header(SESSION_HEADER);
		my $session;
		if(defined($sessionId)) {
			$session = $sessionFactory->retrieve(id => $sessionId);
			unless(defined($session)) {
				# Raise hard error, backend has errors
				$app->log( error => "Unable to authenticate: expired session");
				$app->send_error(ExpiredSession,401);
			}
		} else {
			$app->log( error => "Unable to authenticate: no session");
			$app->send_error(NoSession,401);
		}
		
		# Do we have the credentials?
		my $cas_user = $session->read('cas_user');
		my $cas_pass = $session->read('cas_pass');
		my $cas_service = $session->read('cas_service');
		
		unless(defined($cas_user) && defined($cas_pass) && defined($cas_service)) {
			$sessionFactory->destroy($sessionId);
			$app->log( error => "Unable to authenticate: ".CorruptedSession);
			$app->send_error(CorruptedSession,401);
		}
	
		# Let's authenticate!
		my $cas_auth = Authen::CAS::External->new(
			cas_url => $cas_url,
			username => $cas_user,
			password => $cas_pass
		);
		
		my $cas_response = $cas_auth->authenticate(service => $cas_service);
		if($cas_response->has_notification) {
			$app->log( info => "CAS notification on authentication: ".$cas_response->notification );
		}
		
		my $ticket = $cas_response->service_ticket;
		if(defined($ticket)) {
			$request->var('api_session_id' => $sessionId);
			my $cas = Authen::CAS::Client->new( $cas_url );
			
			$app->log( debug => "Trying to validate via CAS '$cas_version' with ticket=$ticket");
    
			my $r;
			if( $cas_version eq "1.0" ) {
				$r = $cas->validate( $cas_service, $ticket );
			} elsif( $cas_version eq "2.0" ) {
				$r = $cas->service_validate( $cas_service, $ticket );
			} elsif( $cas_version eq "3.0" ) {
				$r = $cas->p3_service_validate( $cas_service, $ticket );
			} else {
				$app->send_error(InvalidConfig .  "cas_version '$cas_version' not supported");
			}
			
			if( $r->is_success ) {
				# Redirect to given path
				$app->log( info => "Authenticated as: ".$r->user);
				if( $cas_version eq "1.0" ) {
					$request->var($cas_user_map => $r->user);
				} else {
					my $attrs = _map_attributes( $r->doc, $mapping , $asArray);
					#$app->log( debug => "Mapped attributes: ".$dsl->to_dumper( $attrs ) );
					$request->var($cas_user_map => $attrs);
				}
				$sessionFactory->flush('session' => $session);
				# Jump to the code
				goto $coderef;
			} elsif( $r->is_failure ) {
				# Redirect to denied
				$app->log( debug => "Failed to authenticate: ".$r->code." / ".$r->message );
				$app->send_error(CasError,401);
			} else {
				# Raise hard error, backend has errors
				$app->log( error => "Unable to authenticate: ".$r->error);
				$app->send_error(CasError . $r->error );
			}
		} else {
			$sessionFactory->destroy($sessionId);
			$app->log( error => FailedToAuthenticate);
			$app->send_error(FailedToAuthenticate,401);
		}
	};

    
}

sub _pre_auth_cas {
	my ( $dsl, $coderef ) = @_;
	
	$settings ||= { _default_conf(), %{ plugin_setting() } };
	#use Data::Dumper;
	#print STDERR Dumper($settings),"\n";
	
	return sub {
		my $app = $dsl->app;
		my $request = $app->request;
		
		my $cas_url = $settings->{cas_url} || $app->send_error(InvalidConfig . "cas_url is unset" );
		my $cas_version = $settings->{cas_version} ||  $app->send_error(InvalidConfig . "cas_version is unset");
		my $cas_user_map = $settings->{cas_user_map};
		
		my $ssl_verify_hostname = $settings->{ssl_verify_hostname};
		$ENV{"PERL_LWP_SSL_VERIFY_HOSTNAME"} = $ssl_verify_hostname;

		# check supported versions
		unless( grep(/$cas_version/, qw( 3.0 2.0 1.0 )) ) {
			$app->send_error(InvalidConfig . "cas_version '$cas_version' not supported");
		}
		
		my $mapping = $settings->{cas_attr_map};
		my $asArray = $settings->{cas_attr_as_array_map};
		my $params = $request->params;
		# Do we have the credentials?
		unless(exists($params->{'username'}) && exists($params->{'password'}) && exists($params->{'service'})) {
			$app->log( error => "Unable to authenticate: ".CorruptedSession);
			$app->send_error(CorruptedSession,401);
		}
		
		my $cas_user = $params->{'username'};
		my $cas_pass = $params->{'password'};
		my $cas_service = $params->{'service'};
		
		# Let's authenticate!
		my $cas_auth = Authen::CAS::External->new(
			cas_url => $cas_url,
			username => $cas_user,
			password => $cas_pass
		);
		
		my $cas_response = $cas_auth->authenticate(service => $cas_service);
		if($cas_response->has_notification) {
			$app->log( info => "CAS notification on authentication: ".$cas_response->notification );
		}
		
		my $ticket = $cas_response->service_ticket;
		if(defined($ticket)) {
			my $cas = Authen::CAS::Client->new( $cas_url );
			
			$app->log( debug => "Trying to validate via CAS '$cas_version' with ticket=$ticket");
    
			my $r;
			if( $cas_version eq "1.0" ) {
				$r = $cas->validate( $cas_service, $ticket );
			} elsif( $cas_version eq "2.0" ) {
				$r = $cas->service_validate( $cas_service, $ticket );
			} elsif( $cas_version eq "3.0" ) {
				$r = $cas->p3_service_validate( $cas_service, $ticket );
			} else {
				$app->send_error(InvalidConfig .  "cas_version '$cas_version' not supported");
			}
			
			if( $r->is_success ) {
				# Redirect to given path
				$app->log( info => "Authenticated as: ".$r->user);
				if( $cas_version eq "1.0" ) {
					$request->var($cas_user_map => $r->user);
				} else {
					my $attrs = _map_attributes( $r->doc, $mapping , $asArray);
					#$app->log( debug => "Mapped attributes: ".$dsl->to_dumper( $attrs ) );
					$request->var($cas_user_map => $attrs);
				}
				
				# We are sure it is working, so let's save
				my $sessionFactory = $app->session_engine;
				my $session = $sessionFactory->create();
				my $sessionId = $session->id();
				
				$request->var('api_session_id' => $sessionId);
				
				$session->write('cas_user' => $cas_user);
				$session->write('cas_pass' => $cas_pass);
				$session->write('cas_service' => $cas_service);
				
				$sessionFactory->flush('session' => $session);
				# Jump to the code
				goto $coderef;
			} elsif( $r->is_failure ) {
				# Redirect to denied
				$app->log( debug => "Failed to authenticate: ".$r->code." / ".$r->message );
				$app->send_error(CasError,401);
			} else {
				# Raise hard error, backend has errors
				$app->log( error => "Unable to authenticate: ".$r->error);
				$app->send_error(CasError . $r->error );
			}
		} else {
			$app->log( error => FailedToAuthenticate);
			$app->send_error(FailedToAuthenticate,401);
		}
	};

    
}

sub _map_attributes {
    my ( $doc, $mapping , $asArray ) = @_;

    my $attrs = {};

    my $result = $doc->find( '/cas:serviceResponse/cas:authenticationSuccess' );
    if( $result ) { 
        my $node = $result->get_node(1);

        # extra all attributes
        my @attributes = $node->findnodes( "./cas:attributes/*" );
        foreach my $a (@attributes) {
            my $name = (split(/:/, $a->nodeName, 2))[1];
            my $val = $a->textContent;
            # Encoding to UTF-8, as parsing fails sometimes
            utf8::encode($val);

		my $mapped_name = $mapping->{ $name } // $name;
		
		if((!exists($attrs->{ $mapped_name }) && (!exists($asArray->{ $mapped_name }) || !$asArray->{ $mapped_name })) || (exists($attrs->{ $mapped_name }) && exists($asArray->{ $mapped_name }) && !$asArray->{ $mapped_name })){
			$attrs->{ $mapped_name } = $val;
		} else {
			$attrs->{ $mapped_name } = []  unless(exists($attrs->{ $mapped_name }));
			$attrs->{ $mapped_name } = [ $attrs->{ $mapped_name } ]  unless(ref($attrs->{ $mapped_name }) eq 'ARRAY');
			
			push(@{$attrs->{ $mapped_name }},$val);
		}
        }
            
    }
    return $attrs;
}


register_plugin for_versions => [2];

1; # End of Dancer2::Plugin::Auth::CAS
__END__

=pod

=head1 VERSION

Version 0.01

=head1 SYNOPSIS

Dancer2::Plugin::Auth::CAS provides CAS single-sign-on authentication

Add the plugin to your application:

    use Dancer2::Plugin::Auth::CAS;

Configure the plugin in your config:

  plugins:
    "Auth::CAS":
        cas_url: "https://your.org/sso"
        cas_denied_path: "/denied"
        cas_version: "2.0"
        cas_user_map: "user"
        cas_attr_map:
            email: "email"
            username: "username"
            firstName: "firstname"
            lastName: "lastname"

or in your code:

  set engines => {
  	plugins => {
  		"Auth::CAS" => {
  			cas_url => "https://your.org/sso",
  			cas_denied_path => "/denied",
  			cas_version => "2.0",
  			cas_user_map => "user",
  			cas_attr_map => {
  				email => "email",
  				username => "username",
  				firstName => "firstname",
  				lastName => "lastname"
  			}
  		}
  	}
  };


Then use it:

    get '/private' => auth_cas login => sub { ... };


=head1 DESCRIPTION

Dancer2::Plugin::Auth::CAS provides single-sign-on (sso) authentication 
via JASIGs Central Authentication Service (CAS). See L<http://www.jasig.org/cas>

=head1 CONFIGURATION

The available configuration options are listed below.

=head2 cas_url

The URL of your CAS server

=head2 cas_denied_path

Redirect towards this path or URL when authentication worked but was simply invalid.

=head2 cas_version

The version of your CAS server, usually '3.0', '2.0' or '1.0'

=head2 cas_user_map

This lets you choose under what name the CAS user details will be stored in your session. Defaults to: 'cas_user'
All user attributes delivered by the CAS-Server will be stored as a HashRef under the session key of C<cas_user_map>. 
Defaults to: 'cas_user'

=head2 cas_attr_map 

This lets you map CAS user attributes towards your own attribute names.

Example:

    cas_attr_map:
        email: "user_email"
        username: "username"
        firstName: "first_name"
        lastName: "last_name"

This will map the CAS user attribute C<email> to C<user_email> aso..
          
=head1 FUNCTIONS

=head2 auth_cas ( %args )

This function may be called in a before filter or at the beginning of a route
handler. It checks if the client is authenticated, else it redirects the client 
towards the CAS-server SSO login URL.

If the login succeeds, the CAS-Server will redirect the client towards the 
first requested path including a 'ticket' as URL parameter. This triggers the C<auth_cas>
a second time, where it validates the 'ticket' against the CAS-Server. If the service ticket
validation fails, it will redirect the client towards the C<cas_denied_path> URL.

Once the ticket validation has been done, the server includes user attributes 
in its reponse to the Dancer application. These user attributes are stored as a HashRef in
a C<session> key (see C<cas_user_map>). These attributes can be renamed/mapped towards
your own keys with the C<cas_attr_map> option.

Parameters:

=over 4

=item * C<ticket> (optional)

If you want to extract the CAS ticket yourself, then you can forward it explicitly with this parameter.

=item * C<cas_denied_path> (optional)

See C<cas_denied_path> in the configuration section.

=item * C<cas_user_map> (optional)

See C<cas_user_map> in the configuration section.

=back

=head1 AUTHOR

Jean Stebens, C<< <cpan.helba at recursor.net> >>
José María Fernández, C<< <jmfernandez at cnio.es> >>

=head1 BUGS

Please report any bugs or feature requests at L<https://github.com/inab/Dancer2-Plugin-Auth-CAS>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.


=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Dancer2::Plugin::Auth::CAS


You can also look for information at: L<https://github.com/inab/Dancer2-Plugin-Auth-CAS>

=head1 LICENSE AND COPYRIGHT

Copyright 2013-2014 Jean Stebens.
Copyright 2016 José María Fernández.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.
=cut


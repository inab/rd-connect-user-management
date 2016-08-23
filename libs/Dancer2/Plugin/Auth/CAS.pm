use 5.008001;
use strict;
use warnings;

# With this patch we support CAS 3.0
use Authen::CAS::Client;
package Authen::CAS::Client;

sub p3_service_validate {
  my ( $self, $service, $ticket, %args ) = @_;
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
#use Authen::CAS::Client;
use Scalar::Util 'blessed';

our $VERSION;

use constant InvalidConfig => "Invalid or missing configuration: ";
use constant CasError => "Unable to auth with CAS backend: ";

my $settings;
my %dispatch = ( login => \&_auth_cas, );

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
		cas_transient_params	=>	'cas_transient_params',
		cas_denied_path	=>	'denied',
		ssl_verify_hostname	=>	1,
		cas_attr_map	=>	{}
	);
}

sub _auth_cas {
	my ( $dsl, $coderef ) = @_;
	
	$settings ||= { _default_conf(), %{ plugin_setting() } };
	use Data::Dumper;
	print STDERR Dumper($settings),"\n";
	
	return sub {
		my $app = $dsl->app;
		my $request = $app->request;
		
		my $base_url = $settings->{cas_url} || $app->send_error(InvalidConfig . "cas_url is unset" );
		my $cas_version = $settings->{cas_version} ||  $app->send_error(InvalidConfig . "cas_version is unset");
		my $cas_user_map = $settings->{cas_user_map};
		my $cas_transient_params = $settings->{cas_transient_params};
		my $cas_denied_url = $settings->{cas_denied_path};

		my $ssl_verify_hostname = $settings->{ssl_verify_hostname};
		$ENV{"PERL_LWP_SSL_VERIFY_HOSTNAME"} = $ssl_verify_hostname;

		# check supported versions
		unless( grep(/$cas_version/, qw( 3.0 2.0 1.0 )) ) {
			$app->send_error(InvalidConfig . "cas_version '$cas_version' not supported");
		}
		
		my $mapping = $settings->{cas_attr_map};
		
		my $ticket = undef;
		$ticket = $settings->{ticket}  if(exists($settings->{ticket}));
		my $params = $request->params;
		unless( $ticket ) {
			my $tickets = $params->{ticket};
			# For the case when application also uses 'ticket' parameters
			# we only remove the real cas service ticket
			if( ref($tickets) eq "ARRAY" ) {
				while( my ($index, $value) = each @$tickets ) {
					# The 'ST-' is specified in CAS-protocol
					if( $value =~ m/^ST\-/ ) {
						$ticket = delete $tickets->[$index];
					}
				}
			} else {
				$ticket = delete $params->{ticket};
			}
		}
		
		# Do we have to restore previous params?
		# We are not going to overwrite a possibly legitimate incoming request
		if(scalar(keys(%{$params})) == 0) {
			my $transient_params = $app->session->read($cas_transient_params);
			$params = $transient_params  if(defined($transient_params));
			$app->session->delete($cas_transient_params);
		}
		
		
		my $user = $app->session->read( $cas_user_map );

		if( $user ) {
			goto $coderef;
		} else {
			# This operation can be dangerous for user creation APIs, as clear passwords could travel
			my $service = $request->uri_for( $request->path_info, $params );
			my $service_naked = $request->header('X-CAS-Referer');
			$service_naked = $request->referer  unless(defined($service_naked));
			$service_naked = $request->uri_for( $request->path_info )  unless(defined($service_naked));
			my $cas = Authen::CAS::Client->new( $base_url );
			
			my $redirect_url;

			if( $ticket) {
				$app->log( debug => "Trying to validate via CAS '$cas_version' with ticket=$ticket");
            
				my $r;
				if( $cas_version eq "1.0" ) {
					$r = $cas->validate( $service_naked, $ticket );
				} elsif( $cas_version eq "2.0" ) {
					$r = $cas->service_validate( $service_naked, $ticket );
				} elsif( $cas_version eq "3.0" ) {
					$r = $cas->p3_service_validate( $service_naked, $ticket );
				} else {
					$app->send_error(InvalidConfig .  "cas_version '$cas_version' not supported");
				}
				
				if( $r->is_success ) {
					# Redirect to given path
					$app->log( info => "Authenticated as: ".$r->user);
					if( $cas_version eq "1.0" ) {
						$app->session->write($cas_user_map => $r->user);
					} else {
						my $attrs = _map_attributes( $r->doc, $mapping );
						$app->log( debug => "Mapped attributes: ".$dsl->to_dumper( $attrs ) );
						$app->session->write($cas_user_map => $attrs);
					}
					$redirect_url = $service;

				} elsif( $r->is_failure ) {
					# Redirect to denied
					$app->log( debug => "Failed to authenticate: ".$r->code." / ".$r->message );
					$redirect_url = $request->uri_for( $cas_denied_url );
				} else {
					# Raise hard error, backend has errors
					$app->log( error => "Unable to authenticate: ".$r->error);
					$app->send_error(CasError . $r->error );
				}
			} else {
				# Has no ticket, needs one
				$redirect_url = $cas->login_url( $service_naked );
				$app->session->write($cas_transient_params,$params);
				$app->log( debug => "Redirecting to CAS: ".$redirect_url );
			}
			
			# General redir response
			return $app->redirect($redirect_url);
		}
	};

    
}

sub _map_attributes {
    my ( $doc, $mapping ) = @_;

    my $attrs = {};

    my $result = $doc->find( '/cas:serviceResponse/cas:authenticationSuccess' );
    if( $result ) { 
        my $node = $result->get_node(1);

        # extra all attributes
        my @attributes = $node->findnodes( "./cas:attributes/*" );
        foreach my $a (@attributes) {
            my $name = (split(/:/, $a->nodeName, 2))[1];
            my $val = $a->textContent;

            my $mapped_name = $mapping->{ $name } // $name;
            $attrs->{ $mapped_name } = $val;
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


#!/usr/bin/perl
# RD-Connect User Management Libraries
# José María Fernández (jose.m.fernandez@bsc.es)

use strict;
use warnings 'all';

package RDConnect::MetaUserManagement::Error;

use Scalar::Util qw(reftype);

# This declaration is needed to be able to serialize this errors from JSON 
sub TO_JSON {
	my $self = shift;
	
	if(reftype($self) eq 'HASH') {
		my %retval = %{$self};
		return \%retval;
	} elsif(reftype($self) eq 'ARRAY') {
		return [@{$self}];
	} elsif(reftype($self) eq 'SCALAR') {
		my $retval = ${$self};
		return \$retval;
	}
}

1;

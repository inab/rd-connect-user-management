#!/usr/bin/perl -w

use strict;

use Net::LDAP::Entry;

my $baseDN = 'ou=people,dc=rd-connect,dc=eu';

my $cnVal = 'José María Fernández';
my $entry = Net::LDAP::Entry->new();
$entry->dn('cn='.$cnVal.','.$baseDN);
$entry->add(
	'givenName'	=>	'José María',
	'sn'	=>	'Fernández',
	'userPassword'	=>	'',
	'objectClass'	=>	 ['basicRDproperties','inetOrgPerson','top'],
	'uid'	=>	'j.m.fernandez',
	'cn'	=>	$cnVal
);

print $entry->ldif();
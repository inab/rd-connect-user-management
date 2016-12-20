#!/bin/sh

(echo y;echo o conf prerequisites_policy follow;echo o conf commit) | cpan
export PERL_LOCAL_LIB_ROOT="$PERL_LOCAL_LIB_ROOT:${HOME}/perl5"
export PERL_MB_OPT="--install_base ${HOME}/perl5"
export PERL_MM_OPT="INSTALL_BASE=""${HOME}""/perl5"
export PERL5LIB="${HOME}/perl5/lib/perl5:$PERL5LIB"
export PATH="${HOME}/perl5/bin:$PATH"
export NO_NETWORK_TESTING=n
cpan -i LWP LWP::Protocol::https Test::More boolean experimental \
Config::IniFiles Net::LDAP MIME::Base64 Digest::MD5 Digest::SHA1 \
JSON::Validator Email::Address Email::MIME \
Email::Sender::Transport::SMTPS Env File::MimeInfo Text::Unidecode && \
(echo y; echo y) | cpan -i Template && \
cpan -i Authen::CAS::Client Authen::CAS::External Dancer2 Plack::Middleware::CrossOrigin Plack::Middleware::Deflater FCGI && exit 0

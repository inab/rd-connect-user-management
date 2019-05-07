requires 'local::lib';
requires 'LWP::UserAgent';
requires 'LWP::Protocol::https';
requires 'Test::More';
requires 'boolean';
requires 'experimental';
requires 'Config::IniFiles';
requires 'Net::LDAP';
requires 'MIME::Base64';
requires 'Digest::MD5';
requires 'Digest::SHA1';
requires 'JSON';
requires 'JSON::MaybeXS';
requires 'JSON::Validator';
requires 'Email::Address';
requires 'Email::MIME';
requires 'Email::Sender::Transport::SMTP';
requires 'Env';
requires 'File::MimeInfo';
requires 'Text::Unidecode';
requires 'Template';
requires 'Moose';
requires 'Authen::CAS::Client';
# Dependency installed later, from command line
requires 'Authen::CAS::External', '== 0.08',
	url	=>	'https://github.com/jmfernandez/perl5-authen-cas-external/archive/v0.80-fix.tar.gz';
requires 'Dancer2';
requires 'Plack::Middleware::CrossOrigin';
requires 'Plack::Middleware::Deflater';
requires 'FCGI';
requires 'URI';
requires 'UUID::Tiny';
requires 'Email::Valid';
requires 'DateTime';
requires 'Data::Password::zxcvbn';
# Dependency installed later, from command line
requires 'Dancer2::Plugin::CSRF', '== 1.02',
	url	=>	'https://github.com/jmfernandez/Dancer2-Plugin-CSRF/archive/1.02.tar.gz';
requires 'Test::Deep';

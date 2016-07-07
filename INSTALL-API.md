# RD-Connect user management API installation

For the user-management REST API these additional dependencies are required:

* Dancer2
* Plack::Middleware::CrossOrigin
* Plack::Middleware::Deflater
* FCGI	(needed by Plack::Handler::FCGI)
* A web server with a proper setup.

## Deployment
1. Check you have installed gcc, cpan, the development version of Perl and [APG](http://www.adel.nursat.kz/apg/ "Another Password Generator") (which is available in EPEL):

	```bash
	yum install -y gcc automake flex bison make patch perl perl-devel perl-CPAN perl-Net-IDN-Encode perl-IO-Compress perl-Net-SSLeay perl-Crypt-SSLeay
	# Next ones are needed only if you don't have them already
	yum install -y epel-release git
	yum install -y apg
	```
	
2. Create user `rdconnect-rest`, with a separate group

	```bash
	useradd -m -U -c 'RD-Connect REST API unprivileged user' rdconnect-rest
	```

3. As the user `rdconnect-rest`, install the needed Perl modules

	```bash
	# Autoconfiguration for CPAN
	(echo y;echo o conf prerequisites_policy follow;echo o conf commit)|cpan
	export PERL_LOCAL_LIB_ROOT="$PERL_LOCAL_LIB_ROOT:/home/rdconnect-rest/perl5";
	export PERL_MB_OPT="--install_base /home/rdconnect-rest/perl5";
	export PERL_MM_OPT="INSTALL_BASE=/home/rdconnect-rest/perl5";
	export PERL5LIB="/home/rdconnect-rest/perl5/lib/perl5:$PERL5LIB";
	export PATH="/home/rdconnect-rest/perl5/bin:$PATH";
	export NO_NETWORK_TESTING=n
	
	cpan -i Test::More boolean experimental Config::IniFiles Net::LDAP MIME::Base64 Digest::MD5 Digest::SHA1 JSON::Validator Email::Address Email::MIME Email::Sender::Transport::SMTPS Env File::MimeInfo Text::Unidecode
	(echo y; echo y) | cpan -i Template::Toolkit
	cpan -i Dancer2 Plack::Middleware::CrossOrigin Plack::Middleware::Deflater FCGI
	```

4. Clone this code, in order to install the API

5. Create directory `DOCUMENT_ROOT`, and copy next content there:

	```bash
	mkdir -p "${HOME}"/DOCUMENT_ROOT/cgi-bin
	cp -dpr user-management user-management.psgi libs "${HOME}"/DOCUMENT_ROOT/cgi-bin
	```

6. Create a file called `user-management.ini`, based on [template-config.ini](template-config.ini), with the connection and authentication parameters to use the LDAP server, as well as the mail server.

## Web server setup with a virtual host (in CentOS)

1. You have to install Apache and [http://mpm-itk.sesse.net/](MPM ITK):
	
	```bash
	yum install -y httpd httpd-itk
	```

2. Now, we switch on MPM ITK *without switching off* MPM prefork:

	```bash
	sed -i 's/^#\(LoadModule \)/\1/' /etc/httpd/conf.modules.d/00-mpm-itk.conf
	```

3. As CentOS does not come with the virtual hosts infrastructure for Apache, we have to create it, and include its usage in the configuration file:

	```bash
	mkdir -p /etc/httpd/sites-available /etc/httpd/sites-enabled
	echo 'IncludeOptional sites-enabled/*.conf' >> /etc/httpd/conf/httpd.conf
	```

4. Copy configuration file apache/RD-Connect.conf to `/etc/httpd/sites-enabled`

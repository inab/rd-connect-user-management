# RD-Connect user management API installation

This document explains how to install and setup RD-Connect User Management REST API.

First, you have to install all the dependencies listed in [README.md]. For the user-management REST API the latest versions of these additional dependencies are required:

* Authen::CAS::Client
* Dancer2
* LWP::Protocol::https
* Plack::Middleware::CrossOrigin
* Plack::Middleware::Deflater
* FCGI	(needed by Plack::Handler::FCGI)
* A web server, like Apache, with a proper setup.

## Deployment
1. Check you have installed gcc, cpan, the development version of Perl and [APG](http://www.adel.nursat.kz/apg/ "Another Password Generator") (which is available in EPEL):

	```bash
	yum install -y gcc automake flex bison make patch perl perl-devel perl-CPAN perl-Net-IDN-Encode perl-IO-Compress perl-Net-SSLeay perl-Crypt-SSLeay perl-XML-LibXML
	# Next ones are needed only if you don't have them already
	yum install -y epel-release git
	yum install -y apg
	```
	
2. Create a separate user (for instance, `rdconnect-rest` with group `rdconnect-rest`), with a separate group

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
	cpan -i Authen::CAS::Client Dancer2 Plack::Middleware::CrossOrigin Plack::Middleware::Deflater FCGI
	```

4. Clone this code, in order to install the API

5. Create a file called `user-management.ini`, based on [template-config.ini](template-config.ini), with the connection and authentication parameters to use the LDAP server, as well as the mail server and the proper setup in `rdconnect-usermanagement-api` section.

6. Create an installation directory (for instance, `/home/rdconnect-rest/RDConnect-UserManagement-REST-API`), and copy at least next content there:

	```bash
	mkdir -p "${HOME}"/RDConnect-UserManagement-REST-API
	cp -dpr user-management.ini user-management.cgi user-management.fcgi user-management.psgi libs "${HOME}"/RDConnect-UserManagement-REST-API
	```

5. Create a directory `DOCUMENT_ROOT`, which will be used to host the [https://github.com/inab/rd-connect-user-management-interface](user interface), and follow the installation procedures in order to put it there.

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

4. Copy template configuration file apache/RD-Connect.conf to `/etc/httpd/sites-enabled`

## Apache Web server setup with a virtual host (in CentOS and Ubuntu)

1. You have to install and setup Apache:
	
	```bash
	# This is for CentOS
	yum install -y httpd
	```
	
	```bash
	# This is for Ubuntu
	apt-get install apache2
	```

2. As CentOS does not come with the virtual hosts infrastructure for Apache, you have to create it, and include its usage in the configuration file:

	```bash
	mkdir -p /etc/httpd/sites-available /etc/httpd/sites-enabled
	echo 'IncludeOptional sites-enabled/*.conf' >> /etc/httpd/conf/httpd.conf
	```

3. If you are going to use `user-management.cgi`, you optionally have to install [http://mpm-itk.sesse.net/](MPM ITK) and enable it *without switching off* MPM prefork, in order to run it as the user you have created:
	
	```bash
	# This is for CentOS
	yum install -y httpd-itk
	sed -i 's/^#\(LoadModule \)/\1/' /etc/httpd/conf.modules.d/00-mpm-itk.conf
	```
	
	```bash
	# This is for Ubuntu
	apt-get install libapache2-mpm-itk
	a2enmod mpm_itk
	```
	
	Next, you have to enable `cgi` module:
	
	```bash
	# This is for Ubuntu
	a2enmod cgi
	```
	
	You have to put next Apache configuration block inside de virtualhost definition, in order to enable the API handler at `/RDConnect-UserManagement-API`:
	
	```
	<IfModule mpm_itk_module>
		AssignUserId rdconnect-rest rdconnect-rest
	</IfModule>
	
	# This line is needed if you locally installed the Perl modules needed
	SetEnv PERL5LIB /home/rdconnect-rest/perl5/lib/perl5
	
	ScriptAlias "/RDConnect-UserManagement-API" "/home/rdconnect-rest/RDConnect-UserManagement-REST-API/user-management.cgi"
	<Directory /home/rdconnect-rest/RDConnect-UserManagement-REST-API>
		AllowOverride None
		SetHandler cgi-script
		Options ExecCGI SymLinksIfOwnerMatch
		
		# These sentences are for Apache 2.2 and Apache 2.4 with mod_access_compat enabled
		<IfModule !mod_authz_core.c>
			Order allow,deny
			Allow from all
		</IfModule>
		
		# This sentence is for Apache 2.4 without mod_access_compat
		<IfModule mod_authz_core.c>
			Require all granted
		</IfModule>
	</Directory>
	```
	
4. If you are going to use `user-management.fcgi` you have to install [https://httpd.apache.org/mod_fcgid/mod/mod_fcgid.html](mod_fcgid):

	
	```bash
	# This is for CentOS
	yum install -y mod_fcgid
	```
	
	```bash
	# This is for Ubuntu
	apt-get install libapache2-mod-fcgid
	a2enmod fcgid
	```
	
	You optionally have to install [https://httpd.apache.org/docs/2.4/mod/mod_suexec.html](mod_suexec), if you want the FCGI run as `rdconnect-rest`
	
	```bash
	# This is for Ubuntu
	apt-get install apache2-suexec
	a2enmod suexec
	```

	You have to put next Apache configuration block inside de virtualhost definition, in order to enable the API handler at `/RDConnect-UserManagement-API`:
	
	```
	<IfModule mod_suexec>
		SuexecUserGroup rdconnect-rest rdconnect-rest
	</IfModule>
	
	
	FcgidIOTimeout 300
	FcgidMaxRequestLen 104857600
	# This line is needed if you locally installed the Perl modules needed
	FcgidInitialEnv PERL5LIB /home/rdconnect-rest/perl5/lib/perl5
	
	ScriptAlias "/RDConnect-UserManagement-API" "/home/rdconnect-rest/RDConnect-UserManagement-REST-API/user-management.fcgi"
	<Directory /home/rdconnect-rest/RDConnect-UserManagement-REST-API>
		AllowOverride None
		SetHandler fcgid-script
		Options ExecCGI SymLinksIfOwnerMatch
		
		# These sentences are for Apache 2.2 and Apache 2.4 with mod_access_compat enabled
		<IfModule !mod_authz_core.c>
			Order allow,deny
			Allow from all
		</IfModule>
		
		# This sentence is for Apache 2.4 without mod_access_compat
		<IfModule mod_authz_core.c>
			Require all granted
		</IfModule>
	</Directory>
	```

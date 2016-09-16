# RD-Connect user management API installation

This document explains how to install and setup RD-Connect User Management REST API.

First, you have to install all the dependencies listed in [README.md]. For the user-management REST API the latest versions of these additional dependencies are required:

* Authen::CAS::Client
* Authen::CAS::External
* Dancer2
* LWP
* LWP::Protocol::https
* Plack::Middleware::CrossOrigin
* Plack::Middleware::Deflater
* FCGI	(needed by Plack::Handler::FCGI)
* A web server, like Apache, with a proper secure setup.

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
	export PERL_LOCAL_LIB_ROOT="$PERL_LOCAL_LIB_ROOT:${HOME}/perl5";
	export PERL_MB_OPT="--install_base ${HOME}/perl5";
	export PERL_MM_OPT="INSTALL_BASE="${HOME}"/perl5";
	export PERL5LIB="${HOME}/perl5/lib/perl5:$PERL5LIB";
	export PATH="${HOME}/perl5/bin:$PATH";
	export NO_NETWORK_TESTING=n
	
	cpan -i LWP LWP::Protocol::https Test::More boolean experimental Config::IniFiles Net::LDAP MIME::Base64 Digest::MD5 Digest::SHA1 JSON::Validator Email::Address Email::MIME Email::Sender::Transport::SMTPS Env File::MimeInfo Text::Unidecode
	(echo y; echo y) | cpan -i Template
	cpan -i Authen::CAS::Client Authen::CAS::External Dancer2 Plack::Middleware::CrossOrigin Plack::Middleware::Deflater FCGI
	```

4. Clone this code, in order to install the API:

	```bash
	cd "${HOME}"
	git clone https://github.com/inab/rd-connect-user-management.git
	cd rd-connect-user-management
	```

5. Create a file called `user-management.ini`, based on [template-config.ini](template-config.ini), with the connection and authentication parameters to use the LDAP server, as well as the mail server, and the proper parameter setup in `rdconnect-usermanagement-api` section.

6. Create an installation directory (for instance, `/home/rdconnect-rest/RDConnect-UserManagement-REST-API`), and copy at least next content there:

	```bash
	mkdir -p "${HOME}"/RDConnect-UserManagement-REST-API
	cp -dpr user-management.ini user-management.cgi user-management.fcgi user-management.psgi libs "${HOME}"/RDConnect-UserManagement-REST-API
	```

  or, alternatively, create a symbolic link:
  
	```bash
	ln -s "${HOME}"/rd-connect-user-management "${HOME}"/RDConnect-UserManagement-REST-API
	```

7. Create a directory `DOCUMENT_ROOT`, which will be used to host the [https://github.com/inab/rd-connect-user-management-interface](user interface), and follow its installation procedures in order to put it there.

8. If SELinux is enabled, we have to give permissions to the different directories:

	```bash
	chmod go+rx /home/rdconnect-rest
	chcon -Rv --type=httpd_sys_content_t /home/rdconnect-rest/DOCUMENT_ROOT
	chcon -Rv --type=httpd_sys_content_t /home/rdconnect-rest/rd-connect-user-management
	chcon -Rv --type=httpd_sys_content_t /home/rdconnect-rest/RDConnect-UserManagement-REST-API
	chcon -Rv --type=httpd_sys_script_exec_t /home/rdconnect-rest/RDConnect-UserManagement-REST-API/user-management.cgi
	```

## Web server setup with a secure virtual host (in CentOS)

1. As root, you have to install Apache, [https://httpd.apache.org/docs/current/mod/mod_ssl.html](mod_ssl) and [http://mpm-itk.sesse.net/](MPM ITK), and enable CGI execution policies on SELinux:
	
	```bash
	yum install -y httpd mod_ssl httpd-itk
	setsebool -P httpd_enable_cgi=1
	setsebool -P httpd_read_user_content=1
	setsebool -P httpd_can_network_connect=1
	setsebool -P httpd_enable_homedirs=1
	cd /home/rdconnect-rest/rd-connect-user-management/selinux
	checkmodule -M -m -o rdconnect-user-management.mod rdconnect-user-management.te
	semodule_package -o rdconnect-user-management.pp -m rdconnect-user-management.mod
	semodule -i rdconnect-user-management.pp
	```

2. Now, we switch on MPM ITK *without switching off* MPM prefork (only if you are using CGI):

	```bash
	sed -i 's/^#\(LoadModule \)/\1/' /etc/httpd/conf.modules.d/00-mpm-itk.conf
	```

3. Inside `/etc/httpd/conf.d/ssl.conf` you have to setup:

	* The document root, adding next lines inside VirtualHost block:
	
		```
		DocumentRoot /home/rdconnect-rest/DOCUMENT_ROOT
		
		<Directory /home/rdconnect-rest/DOCUMENT_ROOT>
			AllowOverride None
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
	
	* The setup for mpm-itk, adding next line inside VirtualHost block:
	
		```
		<IfModule mpm_itk_module>
			AssignUserID rdconnect-rest rdconnect-rest
		</IfModule>
		```
	
	* Optional, change the public and private key (keys SSLCertificateFile and SSLCertificateKeyFile) used by the server, obtaining them from your provider.


	* You have to put next Apache configuration block inside de VirtualHost definition, in order to enable the API handler at `/RDConnect-UserManagement-API`:
	
		```
		ScriptAlias "/RDConnect-UserManagement-API" "/home/rdconnect-rest/RDConnect-UserManagement-REST-API/user-management.cgi"
		<Directory /home/rdconnect-rest/RDConnect-UserManagement-REST-API>
			# This line is needed if you locally installed the Perl modules needed
			SetEnv PERL5LIB /home/rdconnect-rest/perl5/lib/perl5
			# This one is needed to remove a Perl warning
			SetEnv HOME /home/rdconnect-rest
			
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
	
5. If you are going to use `user-management.fcgi` you have to install [https://httpd.apache.org/mod_fcgid/mod/mod_fcgid.html](mod_fcgid):

	
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

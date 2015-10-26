# RD-Connect password emailer
RD-Connect Perl scripts to batch create users from a tabular file with e-mail, name, and possibly preferred username.

This program uses next Perl modules:

* Config::IniFiles
* Net::LDAP , also known as perl-ldap
* Digest::SHA1 (or the corresponding module to encode passwords)
* Email::Address
* Email::MIME
* Email::Sender::Transport::SMTPS
* File::Basename
* File::MimeInfo
* MIME::Base64
* Text::Unidecode

and [APG](http://www.adel.nursat.kz/apg/ "Another Password Generator") program (which must be either declared
in the configuration profile or it must be found in the `PATH`).

For the migration program it also needs:

* DBI and the database modules needed (DBD::SQLite)

which expects next table in the database to be migrated to LDAP:

```sql
CREATE TABLE users (
    username varchar(50) not null,
    password varchar(50) not null,
    fullname varchar(4096) not null,
    email varchar(64) not null,
    active boolean not null,
    primary key(username)
);
```

# Future developments
Currently, the e-mails being sent are not neither signed nor encrypted, which is not satisfactory.

So, the plan to move to encrypted and signed e-mails has two steps.

1. In the first phase, all the e-mails the platform sends are going to be signed using OpenPGP standard.
This requires that all the e-mail addresses sending e-mails have a pair of public/private keys, and their
public keys published in standard servers.

  People who wish to verify the origin of the e-mails will need to use next e-mail client extensions:
  * For Mozilla Thunderbird users, you must install [Enigmail](https://www.enigmail.net/) extension.
  * For Apple Mail users, you must install [GPG Suite](https://gpgtools.org/).
  * For Microsoft Outlook users, you must install [Ggp4win](http://www.gpg4win.org/).
  * For K-9 Mail users, you must install [APG](https://play.google.com/store/apps/details?id=org.thialfihar.android.apg).

2. In the second phase, all the e-mails the platform sends are going to be encrypted and signed using
OpenPGP standard

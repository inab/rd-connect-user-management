# RD-Connect user management programs

RD-Connect Perl scripts to batch create users, groups and their associations.

These programs use next Perl modules:

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

These programs use a configuration profile, which must be based on the provided [template file](template-config.ini).

## RD-Connect user creation and password emailer [create-rd-connect-users.pl](create-rd-connect-users.pl)

This program takes as input a configuration profile, a UTF-8 encoded tabular file whose columns have the meaning described in [README-user-management.md], the file with the message template (either in HTML or in plain text) to be sent to the users once their accounts are created, and optionally 0 or more attachments.

This program also depends on:

* [APG](http://www.adel.nursat.kz/apg/ "Another Password Generator") program (which must be either declared in the configuration profile or it must be found in the `PATH`).

## RD-Connect group and organizational units creation [create-rd-connect-groups.pl](create-rd-connect-groups.pl)

The program takes as input a configuration profile and a UTF-8 encoded tabular file whose columns have the meaning described in [README-user-management.md].

This program has two roles:

1. **Organizational unit creation.** Users are searched under `ou=people,dc=rd-connect,dc=eu`, and in order to ease their organization in the LDAP directory, the previous script puts each user under the organizational unit defined in its input tabular file. This script allows creating such organizational units.

2. **Groups with an owner.** Each user can belong to one or more groups, and each group has an owner. This script allows creating such groups, which can have additional meanings.

## Script to associate users to groups [add-rd-connect-user-group.pl](add-rd-connect-user-group.pl)

The program takes as input a configuration profile and a UTF-8 encoded tabular file whose columns have the meaning described in [README-user-management.md].

This program allows assigning each user to one or more groups. Both the users and the groups must exist.

## Listing scripts

There are several scripts which takes as its single parameter a configuration profile, and list contents of RD-Connect LDAP directory:

* [list-rd-connect-users.pl]: It lists the users of the platform.
* [list-people-organizationUnits.pl]: It lists the organizational units of the platform.
* [list-rd-connect-groups.pl]: It lists the groups declared on the platform.

## LDAP migration script [migrateUsers.pl](ldap-migration/migrateUsers.pl)

The migration program from SQLite to LDAP takes as input a configuration profile, and a UTF-8 encoded tabular file with the correspondence between the usernames and the organizational units where each user is going to be migrated.

The migration program also depends on:

* DBI and the database modules needed (DBD::SQLite)
* It also expects next table in the database to be migrated to LDAP:

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

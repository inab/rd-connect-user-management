# RD-Connect user management programs

RD-Connect Perl scripts to batch create users, groups and their associations.

These programs use next Perl modules:

* Config::IniFiles
* Net::LDAP , also known as [perl-ldap](http://ldap.perl.org/)
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

This program takes as input a configuration profile, a UTF-8 encoded tabular file whose columns have the meaning described in [README-user-management.md](README-user-management.md), the file with the message template (either in HTML or in plain text) to be sent to the users once their accounts are created, and optionally 0 or more attachments.

This program also depends on:

* [APG](http://www.adel.nursat.kz/apg/ "Another Password Generator") program (which must be either declared in the configuration profile or it must be found in the `PATH`).

## RD-Connect group and organizational units creation [create-rd-connect-groups.pl](create-rd-connect-groups.pl)

The program takes as input a configuration profile and a UTF-8 encoded tabular file whose columns have the meaning described in [README-user-management.md](README-user-management.md).

This program has two roles:

1. **Organizational unit creation.** Users are searched under `ou=people,dc=rd-connect,dc=eu`(or what was setup in the configuration profile), and in order to ease their organization in the LDAP directory, the previous script puts each user under the organizational unit defined in its input tabular file. This script allows creating such organizational units.

2. **Groups with an owner.** Each user can belong to one or more groups, and each group has an owner. This script allows creating such groups, which can have additional meanings.

The program is able to do both roles at once. Flag `-s` tells the program to skip organizational unit creation, meanwhile flag `-S` tells the program to skip groups creation.

## Script to associate users to groups [add-rd-connect-user-group.pl](add-rd-connect-user-group.pl)

The program takes as input a configuration profile and a UTF-8 encoded tabular file whose columns have the meaning described in [README-user-management.md](README-user-management.md).

This program allows assigning each user to one or more groups. Both the users and the groups must exist.

## Script to reset passwords [reset-rd-connect-user-password.pl](reset-rd-connect-user-password.pl)

The program takes as input a configuration profile and one or more usernames. Those usernames are matched against `uid` and `mail` attributes in order to find the right user. Then a new password is generated for each user, the user is re-enabled, and an e-mail is sent to the registered e-mail address of the user. The program stops on the first wrong username or when it finishes.

## Script to enable / disable a user [enable-rd-connect-user.pl](enable-rd-connect-user.pl)

The program takes as input a configuration profile, a username and a boolean value enabling or disabling the user. The username is matched against `uid` and `mail` attributes in order to find the right user. If the user is found, it is enabled or disabled accordingly to the command line. The program stops on error or when it finishes.

## Script to send an e-mail to one, many or all the enabled RD-Connect users [send-email-rd-connect-users.pl](send-email-rd-connect-users.pl)

This program takes as input a configuration profile, an optional UTF-8 file, the file with the message template (either in HTML or in plain text) to be sent to the users, and optionally 0 or more attachments.

The input file must contain on each line the `uid` or the `mail` of existing users (disabled ones are skipped). When any of the usernames starts with `@` that username is treated as the `cn` of a group, and all its members are included.

If `-` is used as input file, then all the enabled RD-Connect platform users are considered.

A e-mail based on the template and attachments is sent to each one of the users defined by the input file.

## Listing scripts

There are several scripts which takes as its single parameter a configuration profile, and list contents of RD-Connect LDAP directory:

* [list-rd-connect-users.pl](list-rd-connect-users.pl): It lists the users of the platform.
* [list-people-organizationUnits.pl](list-people-organizationUnits.pl): It lists the organizational units of the platform.
* [list-rd-connect-groups.pl](list-rd-connect-groups.pl): It lists the groups declared on the platform.

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

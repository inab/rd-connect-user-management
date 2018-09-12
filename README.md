# RD-Connect user management programs and API

RD-Connect Perl libraries and scripts to batch create users, groups and their associations.

These programs use Perl modules described in `cpanfile`. Installation instructions are available at [INSTALL.md](INSTALL.md).

These programs use a configuration profile, which must be based on the provided [template file](template-config.ini).

For the user-management REST API see [README-API.md](README-API.md).

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

This program has an optional `-p` parameter, though to give the new password from the command line, instead of generating it with `apg`. With it, the program takes as input a configuration profile, the username  and the new password.

## Script to enable / disable a user [enable-rd-connect-user.pl](enable-rd-connect-user.pl)

The program takes as input a configuration profile, a username and a boolean value enabling or disabling the user. The username is matched against `uid` and `mail` attributes in order to find the right user. If the user is found, it is enabled or disabled accordingly to the command line. The program stops on error or when it finishes.

## Script to reset GDPR acceptance state for a user or a group of them [generate-GDPR-token.pl](generate-GDPR-token.pl)

The program takes as input a configuration profile, and the name of an user or a group (the group name must start with '@' symbol), whose GDPR acceptance state must be resetted. It prints for each user their acceptance token. This script is intended for tests.

## Script to accept GDPR for an user [accept-GDPR-token.pl](accept-GDPR-token.pl)

The script takes as input a configuration profile, the name of an user and the GDPR validation token. If it correct and it was unset, it sets the validation state accordingly. This script is intended for tests.

## Script to reset GDPR acceptance state for a list of users, and send them an e-mail [send-gdpr-email-rd-connect-users.pl](send-gdpr-email-rd-connect-users.pl)

The program takes as input a configuration profile, and a file with the list of usernames or groups of users whose GDPR state must be revalidated. The username is matched against `uid` and `mail` attributes in order to find the right user. For the enabled, found users, the program resets their GDPR acceptance status, and it sends the corresponding e-mails with the validation link.

## Script to send an e-mail to one, many or all the enabled RD-Connect users [send-email-rd-connect-users.pl](send-email-rd-connect-users.pl)

This program takes as input a configuration profile, an optional UTF-8 file, the template title, the file with the message template (either in HTML or in plain text) to be sent to the users, and optionally 0 or more attachments.

The input file must contain on each line the `uid` or the `mail` of existing users (disabled ones are skipped). When any of the usernames starts with `@` that username is treated as the `cn` of a group, and all its members are included.

If `-` is used as input file, then all the enabled RD-Connect platform users are considered.

A e-mail based on the template and attachments is sent to each one of the users defined by the input file.

## Script to send an e-mail to a list of users formatted in the same format obtained from `list-rd-connect-users.pl`  [send-email-rd-connect-list.pl](send-email-rd-connect-list.pl)

This program takes as input a configuration profile, a UTF-8 tabular file, the template title, the file with the message template (either in HTML or in plain text) to be sent to the users, and optionally 0 or more attachments.

The input file must follow the same format as the obtained from `list-rd-connect-users.pl`.

A e-mail based on the template and attachments is sent to each one of the users defined by the input file.


## Template domains management

There are several scripts to manage the mail template domains, used in different points of the RD-Connect user lifecycle:

* [listMailTemplateDomains.pl](listMailTemplateDomains.pl): It lists the template domains, as well as the documents associated to each one.

* [getMailTemplatesFromDomain.pl](getMailTemplatesFromDomain.pl): It takes as input the configuration profile and a domain id. The script saves the mail template and the attachments in a directory, and it shows the title.

* [setMailTemplatesFromDomain.pl](setMailTemplatesFromDomain.pl): It takes as input the configuration profile, the domain id, the title template, the message template and the attachments to be stored in that domain, which replace the original ones. From that point, any operation involving the templates of the domain will use the new ones.

## Listing scripts

There are several scripts which takes as its single parameter a configuration profile, and list contents of RD-Connect LDAP directory:

* [list-rd-connect-users.pl](list-rd-connect-users.pl): It lists the users of the platform, in tabular format.
* [list-people-organizationUnits.pl](list-people-organizationUnits.pl): It lists the organizational units of the platform.
* [list-rd-connect-groups.pl](list-rd-connect-groups.pl): It lists the groups declared on the platform.
* [list-JSON-rd-connect-users.pl](list-JSON-rd-connect-users.pl): It lists the users of the platform, in the same JSON format used by the API.

## Renaming scripts

CAUTION! These scripts are used to rename/move entries in the LDAP directory, which could imply changing many entries at once. Use carefully.

* [rename-rd-connect-users.pl](rename-rd-connect-users.pl): It takes as input the configuration profile, and a file with the correspondences between the old username and the new one. This script is intended for massive username changes, due for instance changes in internal naming conventions.

* [rename-rd-connect-OUs.pl](rename-rd-connect-OUs.pl): It takes as input the configuration profile, and a file with the correspondences between the old organizational unit and the new one. When one of the new organizational units already exists, it receives all the old users from the old one, keeping the already existing members. This script is intended for massive organizational unit changes, due for instance changes in internal naming conventions.

* [rename-rd-connect-group.pl](rename-rd-connect-group.pl): It takes as input the configuration profile, the old group name, and the new one. The new group must not exist.

## Moving and fusing scripts

CAUTION! These scripts are used to move entries in the LDAP directory, which could imply changing many entries at once. Use carefully.

* [move-rd-connect-user.pl](move-rd-connect-user.pl): It takes as input the configuration profile, the username, and the destination organizational unit.

* [fusion-rd-connect-groups.pl](fusion-rd-connect-groups.pl): It takes as input the configuration profile, the old group name, and the new one. The new group must exist, and it will keep all the users, both old and new.

## Removing users and groups

CAUTION! DANGER! These scripts are used to definitively remove users and groups, and these operations cannot be undone!!! Use with extreme care!!!

* [remove-rd-connect-group.pl](remove-rd-connect-group.pl):  This dangerous script takes as input the configuration profile and a group name. If the group exists, it is removed.

* [remove-rd-connect-user.pl](remove-rd-connect-user.pl): This dangerous script takes as input the configuration profile and a username. If the user exists, it is removed. The user is removed from all the groups where it is, and if the user was the sole owner of a group, the group is also removed.

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

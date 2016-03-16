User management file formats
========
All the tools which take as input a tabular file skip those lines which start with are comments, i.e. those starting with `#`.


User creation file format (for [create-rd-connect-users.pl](create-rd-connect-users.pl) and [add-rd-connect-user-group.pl](add-rd-connect-user-group.pl))
--------

[create-rd-connect-users.pl](create-rd-connect-users.pl)(1) and [add-rd-connect-user-group.pl](add-rd-connect-user-group.pl)(2) accept as input a tabular file whose columns have next meaning:

1. E-mail of the user to be created (REQUIRED for 1)

2. Full name of the user (REQUIRED for 1)

3. Suggested username (REQUIRED for 2). If this field is empty, a username based on full name will be derived.

4. Organizational unit short name (REQUIRED for 2), where the LDAP entry is going to hang. If it does not exist, the organizational unit will be created. If this field is empty, the default organizational unit will be used. The contents of this field are split by comma, using only the first element

5. Given name (OPTIONAL). If this field is empty, it will be derived from the full name

6. Surname (OPTIONAL). If this field is empty, it will be derived from the full name

Group and organizational unit creation file format (for [create-rd-connect-groups.pl](create-rd-connect-groups.pl))
--------

[create-rd-connect-groups.pl](create-rd-connect-groups.pl) accepts as input a tabular file whose columns have next meaning:

1. Short group name (REQUIRED). If it is a group, the cn (common name) of the group. If it is an organizational unit, the ou
2. Description (REQUIRED). The description of the group or the organizational unit.
3. Owner(s) (OPTIONAL). If this field is set, the username(s) / uid(s) of the owner(s) of the group (separated by commas). If it is unset, a organizational unit is created instead of a group.
4. Create also OU? (OPTIONAL). If this field is set, and previous field was also set, the script first creates both a groupOfNames and a OU.

User to group association (for [add-rd-connect-user-group.pl](add-rd-connect-user-group.pl))
--------

[add-rd-connect-user-group.pl](add-rd-connect-user-group.pl) also accepts next format:

1. username / uid of the user (REQUIRED)
2. Common name / cn of the group (REQUIRED)

User mailing (for [send-email-rd-connect-users.pl](send-email-rd-connect-users.pl))
--------

The input file must contain on each line the `uid` or the `mail` of existing users (disabled ones are skipped). When any of the usernames starts with `@` that username is treated as the `cn` of a group, and all its members are included.

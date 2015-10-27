User creation file format
========

create-rd-connect-users.pl accepts as input a tabular file whose columns have next meaning:

1. E-mail of the user to be created (REQUIRED)

2. Full name of the user (REQUIRED)

3. Suggested username (OPTIONAL). If this field is empty, a username based on full name will be derived.

4. Organizational unit short name (OPTIONAL), where the LDAP entry is going to hang. If it does not exist, the organizational unit will be created. If this field is empty, the default organizational unit will be used.

5. Given name (OPTIONAL). If this field is empty, it will be derived from the full name

6. Surname (OPTIONAL). If this field is empty, it will be derived from the full name

Group and organizational unit creation file format
========

create-rd-connect-groups.pl accepts as input a tabular file whose columns have next meaning:

1. Short group name (REQUIRED). If it is a group, the cn (common name) of the group. If it is an organizational unit, the ou
2. Description (REQUIRED). The description of the group or the organizational unit.
3. Owner (OPTIONAL). If this field is set, the username / uid of the owner of the group. If it is unset, a organizational unit is created instead of a group.

User to group association
========

add-rd-connect-user-groups.pl

1. username / uid of the user (REQUIRED)
2. Common name / cn of the group (REQUIRED)

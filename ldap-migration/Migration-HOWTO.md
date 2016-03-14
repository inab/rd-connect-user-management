# Migration procedures

Migration procedures from SQLite to LDAP user management involve several steps. The procedure assumes next files:

* The SQLite database with the users to be migrated (`cas-users.sqlite`). This database must have a table with next layout, holding the users:
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

* A configuration profile, to be used along the whole procedure (`migration-profile.ini`). This configuration profile must have declared the full path to `cas-users.sqlite` at configuration parameter `dbistr` under `main` section, as well the connection parameters to the LDAP directory where the users are going to be migrated.

* A file with the declaration of the new OUs (organizational units) and groups (along their owners) (`new-OUs-and-groups.txt`).

* A file with the correspondence of users to OUs and groups (`existing-users.txt`).

* A file with new users. Most of them are needed because they are the owners of groups (`new-users.txt`).

* The template and files to be sent to the new users (`EmailforNeuromicsbetatesters.html`).

## Creation of new OUs using [create-rd-connect-groups.pl](../create-rd-connect-groups.pl)

```bash
perl create-rd-connect-groups.pl -S migration-profile.ini new-OUs-and-groups.txt
```

## User migration using [migrateUsers.pl](migrateUsers.pl) or [migrateSomeUsers.pl](migrateSomeUsers.pl)

The migration program from SQLite to LDAP depends on DBD::SQLite. It takes as input the configuration profile (to be used along the full procedure), and a UTF-8 encoded tabular file following the formats understood by [create-rd-connect-users.pl](create-rd-connect-users.pl) or [add-rd-connect-user-group.pl](add-rd-connect-user-group.pl), with the correspondence between the usernames and the organizational units where each user is going to be migrated.

```bash
perl ldap-migration/migrateUsers.pl migration-profile.ini existing-users.txt
```

If you want to migrate only the users listed in `existing-users.txt`, then use the alternate script:

```bash
perl ldap-migration/migrateSomeUsers.pl migration-profile.ini existing-users.txt
```

## Creation of new users using [create-rd-connect-users.pl](../create-rd-connect-users.pl)

```bash
perl create-rd-connect-users.pl migration-profile.ini new-users.txt EmailforNeuromicsbetatesters.html
```

## Creation of groups using [create-rd-connect-groups.pl](../create-rd-connect-groups.pl)

```bash
perl create-rd-connect-groups.pl -s migration-profile.ini new-OUs-and-groups.txt
```

## Association of users to groups using [add-rd-connect-user-group.pl](../add-rd-connect-user-group.pl)

```bash
perl add-rd-connect-user-group.pl migration-profile.ini existing-users.txt new-users.txt
```

## Migration has finished at this point!

# RD-Connect password emailer
RD-Connect Perl scripts to batch create users from a tabular file with e-mail, name, and possibly preferred username.

This program uses next Perl modules:

* Config::IniFiles
* DBI and the database modules needed (DBD::SQLite)
* Digest::SHA1 (or the corresponding module to encode passwords)
* Email::Address
* Email::MIME
* Email::Sender::Transport::SMTPS
* MooX::Types::MooseLike (Email::Sender::Transport::SMTPS depends on it but it does not declare this dependency).

and [APG](http://www.adel.nursat.kz/apg/ "Another Password Generator") program (which must be either declared
in the configuration profile or it must be found in the `PATH`).

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

```bash
# Plack server
plackup -R libs/RDConnect user-management.psgi

# Create User
curl -X PUT -T userTest.json http://127.0.0.1:5000/users
# Modify user
curl -X POST -T userUpdateTest.json http://127.0.0.1:5000/users/p.palotes
# Modify it back
curl -X POST -T userUpdateTestBack.json http://127.0.0.1:5000/users/dr.garrote

# Create Organizational Unit
curl -X PUT -T peopleOUTest.json http://127.0.0.1:5000/organizationalUnits

```

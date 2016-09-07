```bash
# Plack server
plackup -R libs user-management.psgi

# Create a Login file containing the credentials of some privileged user, and do login
curl -X POST -T loginProfile.json http://127.0.0.1:5000/login

# Check the login token is valid
curl -H "X-RDConnect-UserManagement-Session: V9BSkOgjQAwVT2axWYQNFuqUlvUtGz1l" http://127.0.0.1:5000/login

# Push the mail template

curl -H "X-RDConnect-UserManagement-Session: V9BSkOgjQAwVT2axWYQNFuqUlvUtGz1l" -F cn=mailTemplate.html -F 'description=New User Mail Template' -F documentClass=mailTemplate -F content=@EmailforNeuromicsbetatesters.html http://127.0.0.1:5000/mail/newUser/documents

# Create User (be sure the input JSON contains a valid e-mail address!!!!!!!!!!!!!!)
curl -X PUT -H "X-RDConnect-UserManagement-Session: V9BSkOgjQAwVT2axWYQNFuqUlvUtGz1l" -T userTest.json http://127.0.0.1:5000/users

# Modify user
curl -X POST -H "X-RDConnect-UserManagement-Session: V9BSkOgjQAwVT2axWYQNFuqUlvUtGz1l" -T userUpdateTest.json http://127.0.0.1:5000/users/p.palotes
# Modify it back
curl -X POST -H "X-RDConnect-UserManagement-Session: V9BSkOgjQAwVT2axWYQNFuqUlvUtGz1l" -T userUpdateTestBack.json http://127.0.0.1:5000/users/dr.garrote

# Add user to group -> success
curl -X POST -H "X-RDConnect-UserManagement-Session: V9BSkOgjQAwVT2axWYQNFuqUlvUtGz1l" -T userAddToGroupTest.json http://127.0.0.1:5000/users/p.palotes/groups

# Add user to group -> failure
curl -X POST -H "X-RDConnect-UserManagement-Session: V9BSkOgjQAwVT2axWYQNFuqUlvUtGz1l" -T userAddToGroupTestFail.json http://127.0.0.1:5000/users/p.palotes/groups

# Remove user from group -> success
curl -X DELETE -H "X-RDConnect-UserManagement-Session: V9BSkOgjQAwVT2axWYQNFuqUlvUtGz1l" -T userAddToGroupTest.json http://127.0.0.1:5000/users/p.palotes/groups

# Remove user from group -> failure
curl -X DELETE -H "X-RDConnect-UserManagement-Session: V9BSkOgjQAwVT2axWYQNFuqUlvUtGz1l" -T userAddToGroupTestFail.json http://127.0.0.1:5000/users/p.palotes/groups

# Create Organizational Unit
curl -X PUT -H "X-RDConnect-UserManagement-Session: V9BSkOgjQAwVT2axWYQNFuqUlvUtGz1l" -T peopleOUTest.json http://127.0.0.1:5000/organizationalUnits

```

# RD-Connect user management API

The user-management REST API has next endpoints:

* `GET /users`: It returns the list of registered users (both enabled and disabled).

	* `PUT /users`: It creates a new user. The input must be a JSON document following [userValidation.json](libs/RDConnect/userValidation.json) JSON schema.

	* `GET /users/:user_id`: It returns the user which matches the record, or 404 if not found.
	
	* `POST /users/:user_id`: It modifies an existing user. The input must be a JSON document following [userValidation.json](libs/RDConnect/userValidation.json) JSON schema (but not enforcing the existence of all the keys). Those keys whose value is `null` will be removed.

	* `GET /users/:user_id/picture`: It returns the photo associated to the user which matches the record, or 404 if the user does not exist, or the user does not have an associated photo.

	* `PUT /users/:user_id/picture`: It sets up the photo associated to the user which matches the record, or 404 if the user does not exist. It should be a JPEG photo.

	* `POST /users/:user_id/enable`: It enables a disabled user (privileged operation)

	* `POST /users/:user_id/disable`: It enables a disabled user (privileged operation)
	
	* `GET /users/:user_id/groups`: It lists the ids of the groups / roles where the user is member of.
	
	* `POST /users/:user_id/groups`: It adds the user to the groups / roles mentioned in the input array.
	
	* `DELETE /users/:user_id/groups`: It removes the user from the groups / roles mentioned in the input array.

* `GET /organizationalUnits`: It returns the list of registered organizational units.

	* `PUT /organizationalUnits`: It creates a new organizational unit. The input must be a JSON document following [organizationalUnitValidation.json](libs/RDConnect/organizationalUnitValidation.json) JSON schema.

	* `GET /organizationalUnits/:ou_id`: It returns the organizational unit which matches the record, or 404 if not found.

	* `POST /organizationalUnits/:ou_id`: It modifies an existing organizational unit. The input must be a JSON document following [organizationalUnitValidation.json](libs/RDConnect/organizationalUnitValidation.json) JSON schema (but not enforcing the existence of all the keys). Those keys whose value is `null` will be removed.

	* `GET /organizationalUnits/:ou_id/picture`: It returns the photo associated to the organizational unit which matches the record, or 404 if not found, or the organizational unit does not have an associated photo.

	* `PUT /organizationalUnits/:ou_id/picture`: It sets up the photo associated to the organizational unit which matches the record, or 404 if not found. It should be a JPEG photo.

	* `GET /organizationalUnits/:ou_id/users`: It returns the list of registered users (both enabled and disabled) under this organizational unit which matches the record, or 404 if not found.

* `GET /groups`: It returns the list of registered groups / roles.

	* `PUT /groups`: It creates a new group / role. The input must be a JSON document following [groupValidation.json](libs/RDConnect/groupValidation.json) JSON schema.
	
	* `GET /groups/:group_id`: It returns the group which matches the record, or 404 if not found.

	* `POST /groups/:group_id`: It modifies an existing group features, but not its members or owners. The input must be a JSON document following [groupValidation.json](libs/RDConnect/groupValidation.json) JSON schema (but not enforcing the existence of all the keys). Those keys whose value is `null` will be removed.
	
	* `GET /groups/:group_id/members`: It returns the list of users which are members of this group, or 404 if not found.
	
	* `POST /groups/:group_id/members`: It adds the users in the input array to the group as members.
	
	* `DELETE /groups/:group_id/members`: It removes the users in the input array from the group as members.
	
	* `GET /groups/:group_id/owners`: It returns the list of users which are owners of this group, or 404 if not found.

	* `POST /groups/:group_id/owners`: It adds the users in the input array to the group as owners.
	
	* `DELETE /groups/:group_id/owners`: It removes the users in the input array from the group as owners.
	

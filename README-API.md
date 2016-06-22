# RD-Connect user management API

The user-management REST API has next endpoints:

* `GET /users`: It returns the list of registered users (both enabled and disabled).

	* `PUT /users`: It creates a new user. The input must be a JSON document following [userValidation.json](libs/RDConnect/useValidation.json) JSON schema.

	* `GET /users/:user_id`: It returns the user which matches the record, or 404 if not found.
	
	* `POST /users/:user_id`: It modifies an existing user. The input must be a JSON document following [userValidation.json](libs/RDConnect/useValidation.json) JSON schema (but not enforcing the existence of all the keys). Those keys whose value is `null` will be removed.

	* `GET /users/:user_id/picture`: It returns the photo associated to the user which matches the record, or 404 if the user does not exist, or the user does not have an associated photo.

	* `PUT /users/:user_id/picture`: It sets up the photo associated to the user which matches the record, or 404 if the user does not exist. It should be a JPEG photo.

	* `POST /users/:user_id/enable`: It enables a disabled user (privileged operation)

	* `POST /users/:user_id/disable`: It enables a disabled user (privileged operation)

* `GET /organizationalUnits`: It returns the list of registered organizational units.

	* `GET /organizationalUnits/:ou_id`: It returns the organizational unit which matches the record, or 404 if not found.

	* `GET /organizationalUnits/:ou_id/picture`: It returns the photo associated to the organizational unit which matches the record, or 404 if not found, or the organizational unit does not have an associated photo.

	* `PUT /organizationalUnits/:ou_id/picture`: It sets up the photo associated to the organizational unit which matches the record, or 404 if not found. It should be a JPEG photo.

	* `GET /organizationalUnits/:ou_id/users`: It returns the list of registered users (both enabled and disabled) under this organizational unit which matches the record, or 404 if not found.

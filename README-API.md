# RD-Connect user management API

The user-management REST API has next endpoints:

* `GET /users`: It returns the list of registered users (both enabled and disabled).

	* `GET /users/:user_id`: It returns the user which matches the record, or 404 if not found.

	* `GET /users/:user_id/jpegPhoto`: It returns the photo associated to the user which matches the record, or 404 if the user does not exist, or the user does not have an associated photo.

	* `PUT /users/:user_id/jpegPhoto`: It sets up the photo associated to the user which matches the record, or 404 if the user does not exist. It should be a JPEG photo.

	* `POST /users/:user_id/enable`: It enables a disabled user (privileged operation)

	* `POST /users/:user_id/disable`: It enables a disabled user (privileged operation)

* `GET /organizationalUnits`: It returns the list of registered organizational units.

	* `GET /organizationalUnits/:ou_id`: It returns the organizational unit which matches the record, or 404 if not found.

	* `GET /organizationalUnits/:ou_id/users`: It returns the list of registered users (both enabled and disabled) under this organizational unit which matches the record, or 404 if not found.

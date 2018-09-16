# RD-Connect user management API

The user-management REST API has many services. In order to use almost any of them, you have to send a custom HTTP header, which contains the authentication token:

* `X-RDConnect-UserManagement-Session`: The session associated to the logged in user.

The services under the endpoint have several levels of authorization, which require authentication (i.e. they need the custom header). If the logged in user does not have enough privileges to do an operation, this one is denied. When no authorization is required, no authentication is either. The authorization levels are:

* **Any user** `[any]`: The operation is allowed to any user (i.e. authentication but no authorization checks).
* **Admin** `[adm]`: Only users with the administrator role are allowed to do these operations.
* **User** `[u]`: The operation is only allowed to the current user (and admins).
* **PI** `[pi]`: The operation is only allowed to users whose `userCategory` is PI (and admins).
* **Owner** `[own]`: The operation is only allowed to the owner of the group (and admins).

## The services under the endpoint

* `GET /`: It returns basic REST API information, like the CAS server to be used.

* `GET /login` `[any]`: It returns basic information about the logged in user.

* `POST /login`: Sending a JSON document of type `{'username': 'theusername', 'password': 'theSECRETpassword;-)', 'service': 'http://serviceurltorequestticketsfor'}`, the user is logged in if the credentials are valid. The URI of the service is needed to obtain a [https://apereo.github.io/cas/4.2.x/protocol/CAS-Protocol.html](CAS service ticket). It is usually the one which is calling the user-management REST API. This method returns a JSON document in the format `{'session_id': 'theSESSIONid'}`, plus other additional keys from the logged-in user profile. The obtained `session_id` is reused on later calls through `X-RDConnect-UserManagement-Session` header.

* `GET /logout` `[any]`: The user associated to the given session is logged out.

* `GET /mail`: It returns the different available mail templates domains
    * `GET /mail?schema`: It returns the JSON Schema which validates a mail submission (i.e. [mailValidation.json](libs/RDConnect/mailValidation.json)).

	* `POST /mail` `[adm]`: An administrator uses this endpoint to send an e-mail to everybody, or a subset of users, organizational units or groups. The input must be a JSON document following [mailValidation.json](libs/RDConnect/mailValidation.json) JSON schema (but not enforcing the existence of all the keys).
	
	* `GET /mail/:api_key`: It returns the information about this template mail domain.
	
	* `GET /mail/:api_key/documents` `[adm]`: It lists the documents for this template domain, which are the mail template and the attachments (like user agreements and so). It follows [documentValidation.json](libs/RDConnect/documentValidation.json) JSON schema.

	* `POST /mail/:api_key/documents` `[adm]`: It attaches the described document in the multipart/form-data transferred field to this user. The valid parameters are 'cn' (the name), 'description', 'documentClass' and 'content' (this last is the uploaded document).

	* `GET /mail/:api_key/documents/:document_name` `[adm]`: It gets the contents of an specific document.

	* `PUT /mail/:api_key/documents/:document_name` `[adm]`: It replaces the contents of an specific document.

	* `DELETE /mail/:api_key/documents/:document_name` `[adm]`: It removes an specific document.

	* `GET /mail/:api_key/documents/:document_name/metadata` `[adm]`: It gets the metadata of an specific document. It follows [documentValidation.json](libs/RDConnect/documentValidation.json) JSON schema.

	* `POST /mail/:api_key/documents/:document_name/metadata` `[adm]`: A document following [documentValidation.json](libs/RDConnect/documentValidation.json) JSON schema is used to modify the metadata of the document.

* `GET /enabledUsers`: It returns the list of enabled registered users, along with their validated e-mails. ()

	* `GET /enabledUsers?schema`: It returns the JSON Schema which validates the output of /enabledUsers

* `GET /users`: It returns the list of registered users (both enabled and disabled).
	
	* `GET /users?schema`: It returns the JSON Schema which validates a user entry (i.e. [userValidation.json](libs/RDConnect/userValidation.json)).
	
	* `PUT /users` `[adm]`: It creates a new user. The input must be a JSON document following [userValidation.json](libs/RDConnect/userValidation.json) JSON schema.

	* `GET /users/:user_id`: It returns the user which matches the record, or 404 if not found. It follows [userValidation.json](libs/RDConnect/userValidation.json) JSON schema.
	
	* `POST /users/:user_id` `[u]`: It modifies an existing user. The input must be a JSON document following [userValidation.json](libs/RDConnect/userValidation.json) JSON schema (but not enforcing the existence of all the keys). Those keys whose value is `null` will be removed.
	
	* `DELETE /users/:user_id` `[adm]`: It removes an user, fulfilling the restrictions.

	* `POST /users/:user_id/_mail` `[u]`: An administrator (or the same user) uses this endpoint to send an e-mail to this specific user. The input must be a JSON document following [mailValidation.json](libs/RDConnect/mailValidation.json) JSON schema (but not enforcing the existence of all the keys).
	
	* `GET /users/:user_id/picture`: It returns the photo associated to the user which matches the record, or 404 if the user does not exist, or the user does not have an associated photo.

	* `PUT /users/:user_id/picture` `[u]`: It sets up the photo associated to the user which matches the record, or 404 if the user does not exist. It should be a JPEG photo.

	* `POST /users/:user_id/enable` `[adm]`: It enables a disabled user (privileged operation)

	* `POST /users/:user_id/disable` `[u]`: It disables an enabled user (privileged operation)
	
	* `POST /users/:user_id/migratesTo/:ou_id` `[adm]`: It moves a user to a different organizational unit

	* `POST /users/:user_id/renamesTo/:new_user_id` `[adm]`: It renames a user

	* `GET /users/:user_id/acceptGDPR/:token`: It validates a GDPR acceptation token (it produces a redirection).
	
	* `POST /users/:user_id/resetPassword` `[u]`: It resets the password, optionally to the given one in `userPassword` object key. If the user is disabled it enables it (privileged operation)

	* `GET /users/:user_id/groups`: It lists the ids of the groups / roles where the user is member of.
	
	* `POST /users/:user_id/groups` `[adm]`: It adds the user to the groups / roles mentioned in the input array.
	
	* `DELETE /users/:user_id/groups` `[u]`: It removes the user from the groups / roles mentioned in the input array.
	
	* `GET /users/:user_id/documents` `[u]`: It lists the documents (for instance, the user agreement) for this user. It follows [documentValidation.json](libs/RDConnect/documentValidation.json) JSON schema.

	* `POST /users/:user_id/documents` `[u]`: It attaches the described document in the multipart/form-data transferred field to this user. The valid parameters are 'cn' (the name), 'description', 'documentClass' and 'content' (this last is the uploaded document).

	* `GET /users/:user_id/documents/:document_name` `[u]`: It gets the contents of an specific document for this user.

	* `PUT /users/:user_id/documents/:document_name` `[u]`: It replaces the contents of an specific document for this user.

	* `DELETE /users/:user_id/documents/:document_name` `[u]`: It removes an specific document for this user.

	* `GET /users/:user_id/documents/:document_name/metadata` `[u]`: It gets the metadata of an specific document for this user. It follows [documentValidation.json](libs/RDConnect/documentValidation.json) JSON schema.

	* `POST /users/:user_id/documents/:document_name/metadata` `[u]`: A document following [documentValidation.json](libs/RDConnect/documentValidation.json) JSON schema is used to modify the metadata of the document.

* `GET /organizationalUnits`: It returns the list of registered organizational units.
	
	* `GET /organizationalUnits?schema`: It returns the JSON Schema which validates an organizational unit entry (i.e. [organizationalUnitValidation.json](libs/RDConnect/organizationalUnitValidation.json)).
	
	* `PUT /organizationalUnits` `[adm]`: It creates a new organizational unit. The input must be a JSON document following [organizationalUnitValidation.json](libs/RDConnect/organizationalUnitValidation.json) JSON schema.

	* `GET /organizationalUnits/:ou_id`: It returns the organizational unit which matches the record, or 404 if not found. It follows [organizationalUnitValidation.json](libs/RDConnect/organizationalUnitValidation.json) JSON schema.

	* `POST /organizationalUnits/:ou_id` `[adm]`: It modifies an existing organizational unit. The input must be a JSON document following [organizationalUnitValidation.json](libs/RDConnect/organizationalUnitValidation.json) JSON schema (but not enforcing the existence of all the keys). Those keys whose value is `null` will be removed.

	* `POST /organizationalUnits/:ou_id/renamesTo/:new_ou_id` `[adm]`: It renames the organizational unit to a new one

	* `POST /organizationalUnits/:ou_id/mergesTo/:new_ou_id` `[adm]`: It moves all the members of the organizational unit to a new or existing one, disappearing the original organizational unit

	* `GET /organizationalUnits/:ou_id/picture`: It returns the photo associated to the organizational unit which matches the record, or 404 if not found, or the organizational unit does not have an associated photo.

	* `PUT /organizationalUnits/:ou_id/picture` `[adm]`: It sets up the photo associated to the organizational unit which matches the record, or 404 if not found. It should be a JPEG photo.

	* `GET /organizationalUnits/:ou_id/users`: It returns the list of registered users (both enabled and disabled) under this organizational unit which matches the record, or 404 if not found.

	* `POST /organizationalUnits/:ou_id/users/_mail` `[pi]`: An administrator uses this endpoint to send an e-mail to all the members of the organizational unit. The input must be a JSON document following [mailValidation.json](libs/RDConnect/mailValidation.json) JSON schema (but not enforcing the existence of all the keys).
	
* `GET /groups`: It returns the list of registered groups / roles.
	
	* `GET /groups?schema`: It returns the JSON Schema which validates a group entry (i.e. [groupValidation.json](libs/RDConnect/groupValidation.json)).
	
	* `PUT /groups` `[pi]`: It creates a new group / role. The input must be a JSON document following [groupValidation.json](libs/RDConnect/groupValidation.json) JSON schema.
	
	* `GET /groups/:group_id`: It returns the group which matches the record, or 404 if not found. It follows [groupValidation.json](libs/RDConnect/groupValidation.json) JSON schema.

	* `POST /groups/:group_id` `[own]`: It modifies an existing group features, but not its members or owners. The input must be a JSON document following [groupValidation.json](libs/RDConnect/groupValidation.json) JSON schema (but not enforcing the existence of all the keys). Those keys whose value is `null` will be removed.
	
	* `DELETE /groups/:group_id` `[own]`: It removes the group.
	
	* `POST /groups/:group_id/renamesTo/:new_group_id` `[own]`: It renames the group or 404 if not found.
	
	* `POST /groups/:group_id/mergesTo/:new_group_id` `[adm]`: It moves all the members of this group to another existing one, or 404 if not found.
	
	* `GET /groups/:group_id/members`: It returns the list of users which are members of this group, or 404 if not found.
	
	* `POST /groups/:group_id/members` `[own]`: It adds the users in the input array to the group as members.
	
	* `DELETE /groups/:group_id/members` `[own]`: It removes the users in the input array from the group as members.
	
	* `POST /groups/:group_id/members/_mail` `[own]`: An administrator or an owner uses this endpoint to send an e-mail to all the members of the group. The input must be a JSON document following [mailValidation.json](libs/RDConnect/mailValidation.json) JSON schema (but not enforcing the existence of all the keys).
	
	* `GET /groups/:group_id/owners`: It returns the list of users which are owners of this group, or 404 if not found.

	* `POST /groups/:group_id/owners` `[own]`: It adds the users in the input array to the group as owners.
	
	* `DELETE /groups/:group_id/owners` `[own]`: It removes the users in the input array from the group as owners.
	
	* `GET /groups/:group_id/documents` `[own]`: It lists the documents attached to this group, role. It follows [documentValidation.json](libs/RDConnect/documentValidation.json) JSON schema.

	* `POST /groups/:group_id/documents` `[own]`: It attaches the described document in the multipart/form-data transferred field to this group, role. The valid parameters are 'cn' (the name), 'description', 'documentClass' and 'content' (this last is the uploaded document).

	* `GET /groups/:group_id/documents/:document_name` `[own]`: It gets the contents of an specific document for this group.

	* `PUT /groups/:group_id/documents/:document_name` `[own]`: It replaces the contents of an specific document for this group.

	* `DELETE /groups/:group_id/documents/:document_name` `[own]`: It removes an specific document for this group.

	* `GET /groups/:group_id/documents/:document_name/metadata` `[own]`: It gets the metadata of an specific document for this group. It follows [documentValidation.json](libs/RDConnect/documentValidation.json) JSON schema.

	* `POST /groups/:group_id/documents/:document_name/metadata` `[own]`: A document following [documentValidation.json](libs/RDConnect/documentValidation.json) JSON schema is used to update the document metadata.

* GET '/documents?schema': It returns the JSON Schema which validates a document entry.

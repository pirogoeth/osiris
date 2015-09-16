from pyramid.interfaces import IAuthenticationPolicy
from pyramid.httpexceptions import HTTPInternalServerError
from osiris.errorhandling import OAuth2ErrorHandler
from osiris.generator import generate_token
from pyramid.settings import asbool


def password_authorization(request, username, password, scope, expires_in):

    ldap_enabled = asbool(request.registry.settings.get('osiris.ldap_enabled'))
    ldap_scope_as_group = asbool(
        request.registry.settings.get('osiris.ldap_scope_as_group'))

    if ldap_enabled:
        from osiris import get_ldap_connector
        connector = get_ldap_connector(request)
        identity = connector.authenticate(username, password)
        if ldap_scope_as_group and scope:
            user_groups = connector.user_groups(username)
            user_groups = [group[0] for group in user_groups]
            user_groups = [group.split(",")[0].split("=")[1]
                           for group in user_groups]
            if scope not in user_groups:
                return OAuth2ErrorHandler.error_invalid_scope()

    else:
        policy = request.registry.queryUtility(IAuthenticationPolicy)
        authapi = policy._getAPI(request)
        credentials = {'login': username, 'password': password}

        identity, headers = authapi.login(credentials)
        user_groups = []

    if not identity:
        return OAuth2ErrorHandler.error_invalid_grant()
    else:
        storage = request.registry.osiris_store
        # Check if an existing token for the username and scope is already issued
        issued = storage.retrieve(username=username, scope=scope)
        if issued:
            # Return the already issued one
            return dict(access_token=issued.get('token'),
                        token_type='bearer',
                        scope=issued.get('scope'),
                        expires_in=issued.get('expire_time'),
                        )
        else:
            # Create and store token
            token = generate_token()
            stored = storage.store(token, username, scope, expires_in)

            # Issue token
            if stored:
                return dict(access_token=token,
                            token_type='bearer',
                            scope=scope,
                            expires_in=int(expires_in)
                            )
            else:
                # If operation error, return a generic server error
                return HTTPInternalServerError()

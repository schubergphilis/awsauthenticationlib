=====
Usage
=====


To develop on awsauthenticationlib:

.. code-block:: bash

    # The following commands require pipenv as a dependency

    # To lint the project
    _CI/scripts/lint.py

    # To execute the testing
    _CI/scripts/test.py

    # To create a graph of the package and dependency tree
    _CI/scripts/graph.py

    # To build a package of the project under the directory "dist/"
    _CI/scripts/build.py

    # To see the package version
    _CI/scripts/tag.py

    # To bump semantic versioning [--major|--minor|--patch]
    _CI/scripts/tag.py --major|--minor|--patch

    # To upload the project to a pypi repo if user and password are properly provided
    _CI/scripts/upload.py

    # To build the documentation of the project
    _CI/scripts/document.py


To use awsauthenticationlib in a project:

.. code-block:: python

    from awsauthenticationlib import AwsAuthenticator
    awsauth = AwsAuthenticator('arn:aws:iam::ACCOUNTID:role/SomeRoleWithAdminRights')


    awsauth.get_signed_url()
    >>> 'https://signin.aws.amazon.com/federation?Action=login&Issuer=Example.com&Destination=https%3A%2F%2Fconsole.aws.amazon.com&SigninToken=real_long_valid_token_here'


    awsauth.get_control_tower_authenticated_session()
    >>> <requests.sessions.Session object at 0xaddress>


    awsauth.get_sso_authenticated_session()
    >>> <requests.sessions.Session object at 0xaddress>


    awsauth=AwsAuthenticator('arn:aws:iam::ACCOUNTID:role/NoRightsOrWrongRole')
    >>> awsauthenticationlib.awsauthenticationlibexceptions.InvalidCredentials: An error occurred (AccessDenied) when calling the AssumeRole operation: User: arn:aws:sts::ACCOUNTID:assumed-role/AWSReservedSSO_AWSAdministratorAccess_abcdefghij1234/someone@domain.com is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::ACCOUNTID:role/NoRightsOrWrongRole


    awsauth.assumed_role_credentials
    >>> {'aws_access_key_id': 'VALIDACCESSKEY', 'aws_secret_access_key': 'VALIDSECRETKEY', 'aws_session_token': 'VALIDSESSIONTOKEN'}


    awsauth.session_credentials
    >>> {'sessionId': 'VALIDSESSIONID', 'sessionKey': 'VALIDSESSIONKET', 'sessionToken': 'VALIDSESSIONTOKEN'}

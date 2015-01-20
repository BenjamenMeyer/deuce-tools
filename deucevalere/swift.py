#!/usr/bin/python3
import argparse
import datetime
import json
import logging
import sys
import traceback

import deuceclient.auth.nonauth as noauth
import deuceclient.auth.openstackauth as openstackauth
import deuceclient.auth.rackspaceauth as rackspaceauth
import swiftclient.client as swift_client


def __api_operation_prep(log, arguments):
    """
    API Operation Common Functionality
    """
    # Parse the user data
    example_user_config_json = """
    {
        'user': <username>,
        'username': <username>,
        'user_name': <username>,
        'user_id': <userid>
        'tenant_name': <tenantname>,
        'tenant_id': <tenantid>,
        'apikey': <apikey>,
        'password': <password>,
        'token': <token>
    }

    Note: Only one of user, username, user_name, user_id, tenant_name,
          or tenant_id must be specified.

    Note: Only one of apikey, password, token must be specified.
        Token preferred over apikey or password.
        Apikey preferred over password.
    """
    auth_url = arguments.auth_service_url
    auth_provider = arguments.auth_service

    auth_data = {
        'user': {
            'value': None,
            'type': None
        },
        'credentials': {
            'value': None,
            'type': None
        }
    }

    def find_user(data):
        user_list = [
            ('user', 'user_name'),
            ('username', 'user_name'),
            ('user_name', 'user_name'),
            ('user_id', 'user_id'),
            ('tenant_name', 'tenant_name'),
            ('tenant_id', 'tenant_id'),
        ]

        for u in user_list:
            try:
                auth_data['user']['value'] = user_data[u[0]]
                auth_data['user']['type'] = u[1]
                return True
            except LookupError:
                pass

        return False

    def find_credentials(data):
        credential_list = ['token', 'password', 'apikey']
        for credential_type in credential_list:
            try:
                auth_data['credentials']['value'] = user_data[credential_type]
                auth_data['credentials']['type'] = credential_type
                return True
            except LookupError:
                pass

        return False

    user_data = json.load(arguments.user_config)
    if not find_user(user_data):
        sys.stderr.write('Unknown User Type.\n Example Config: {0:}'.format(
            example_user_config_json))
        sys.exit(-2)

    if not find_credentials(user_data):
        sys.stderr.write('Unknown Auth Type.\n Example Config: {0:}'.format(
            example_user_config_json))
        sys.exit(-3)

    # Setup the Authentication
    datacenter = arguments.datacenter

    asp = None
    if auth_provider == 'openstack':
        asp = openstackauth.OpenStackAuthentication

    elif auth_provider == 'rackspace':
        asp = rackspaceauth.RackspaceAuthentication

    else:
        sys.stderr.write('Unknown Authentication Service Provider'
                         ': {0:}'.format(auth_provider))
        sys.exit(-4)

    auth_engine = asp(userid=auth_data['user']['value'],
                      usertype=auth_data['user']['type'],
                      credentials=auth_data['credentials']['value'],
                      auth_method=auth_data['credentials']['type'],
                      datacenter=datacenter,
                      auth_url=auth_url)

    # Auth right away
    auth_token = auth_engine.AuthToken

    # Get the service catalog
    service_catalog = auth_engine.get_client().service_catalog

    # Find Cloud Files
    swift_endpoints = service_catalog.get_endpoints(
        region_name=datacenter.upper(),
        service_name="cloudFiles",
        service_type="object-store")
    swift_url = None
    for url_type, endpoints in swift_endpoints.items():
        for end_point in endpoints:
            if 'publicURL' in end_point:
                swift_url = end_point['publicURL']
                break

    if swift_url is None:
        sys.stderr.write(
            'Unable to locate a Swift End-Point for the specified User')
        sys.exit(-5)

    # Create a swift client to use
    the_swift_client = swift_client.Connection(
        preauthurl=swift_url, preauthtoken=auth_engine.AuthToken, snet=False)

    # And return the stuff required...
    return (auth_engine, swift_url, the_swift_client)


def vault_list(log, arguments):
    auth_service, swift_url, the_client = __api_operation_prep(log, arguments)

    vault_listing = the_client.get_account(marker=arguments.marker,
                                           limit=arguments.limit)
    if not arguments.list_only:
        print('Vaults:')
    for vault in vault_listing[1]:
        print("\t{0}".format(str(vault['name'])))


def vault_object_delete(log, arguments):
    auth_service, swift_url, the_client = __api_operation_prep(log, arguments)

    try:
        the_client.delete_object(arguments.vault_name,
                                 arguments.storage_block_id)
        print('Vault: {0}'.format(arguments.vault_name))
        print('\tSuccessfully deleted {0}'.format(arguments.storage_block_id))
    except Exception as ex:
        print('\tFailed to delete {0}'.format(arguments.storage_block_id))
        print('\t{0} : {1}'.format(ex.msg, ex.http_reason))


def vault_object_list(log, arguments):
    auth_service, swift_url, the_client = __api_operation_prep(log, arguments)

    vault_object_listing = the_client.get_container(arguments.vault_name,
                                                    marker=arguments.marker,
                                                    limit=arguments.limit)
    if not arguments.list_only:
        print('Vault: {0}'.format(arguments.vault_name))
        print('Objects:')
    for vault_object in vault_object_listing[1]:
        print("\t{0}".format(str(vault_object['name'])))


def main():
    arg_parser = argparse.ArgumentParser(
        description="Deuce Swift Client")

    arg_parser.add_argument('--user-config',
                            default=None,
                            type=argparse.FileType('r'),
                            required=True,
                            help='JSON file containing username and API Key')
    arg_parser.add_argument('-lg', '--log-config',
                            default=None,
                            type=str,
                            dest='logconfig',
                            help='log configuration file')
    arg_parser.add_argument('-dc', '--datacenter',
                            default='ord',
                            type=str,
                            dest='datacenter',
                            required=True,
                            help='Datacenter the system is in',
                            choices=['lon', 'syd', 'hkg', 'ord', 'iad', 'dfw'])
    arg_parser.add_argument('--auth-service',
                            default='rackspace',
                            type=str,
                            required=False,
                            help='Authentication Service Provider',
                            choices=['openstack', 'rackspace'])
    arg_parser.add_argument('--auth-service-url',
                            default=None,
                            type=str,
                            required=False,
                            help='Authentication Service Provider URL')
    sub_argument_parser = arg_parser.add_subparsers(title='subcommands')

    def add_limit_argument(p):
        p.add_argument('--limit',
                       default=None,
                       type=int,
                       required=False,
                       help='Return only the specified number of results')

    def add_marker_argument(p):
        p.add_argument('--marker',
                       default=None,
                       type=str,
                       required=False,
                       help='starting point to list from')

    def add_list_only_argument(p):
        p.add_argument('--list-only',
                       default=False,
                       action='store_true',
                       required=False,
                       help='Only show the list, no headers')

    vault_parser = sub_argument_parser.add_parser('vault')
    vault_sub_parser = vault_parser.add_subparsers(title="operations",
                                                   help="Vault Operations")

    vault_list_parser = vault_sub_parser.add_parser('list')
    add_limit_argument(vault_list_parser)
    add_marker_argument(vault_list_parser)
    add_list_only_argument(vault_list_parser)
    vault_list_parser.set_defaults(func=vault_list)

    vault_object_parser = vault_sub_parser.add_parser('object')
    vault_object_parser.add_argument('--vault-name',
                                     default=None,
                                     required=True,
                                     help="Vault Name")
    vault_object_sub_parser = vault_object_parser.add_subparsers(
        title="operations", help="Vault Object Operations")

    vault_object_list_parser = vault_object_sub_parser.add_parser('list')
    add_limit_argument(vault_object_list_parser)
    add_marker_argument(vault_object_list_parser)
    add_list_only_argument(vault_object_list_parser)
    vault_object_list_parser.set_defaults(func=vault_object_list)

    vault_object_delete_parser = vault_object_sub_parser.add_parser('delete')
    vault_object_delete_parser.add_argument('--storage-block-id',
                                            default=None,
                                            required=True,
                                            help="Vault Storage Block Object "
                                            "to Delete")
    vault_object_delete_parser.set_defaults(func=vault_object_delete)

    arguments = arg_parser.parse_args()

    # If the caller provides a log configuration then use it
    # Otherwise we'll add our own little configuration as a default
    # That captures stdout and outputs to .deuce_valere-py.log
    if arguments.logconfig is not None:
        logging.config.fileConfig(arguments.logconfig)
    else:
        lf = logging.FileHandler('.swift-py.log')
        lf.setLevel(logging.DEBUG)

        log = logging.getLogger()
        log.addHandler(lf)
        log.setLevel(logging.DEBUG)

    logging.captureWarnings(True)
    # Build the logger
    log = logging.getLogger()

    return arguments.func(log, arguments)


if __name__ == "__main__":
    sys.exit(main())

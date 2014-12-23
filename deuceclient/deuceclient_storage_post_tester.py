#!/home/bmeyer/rackspace/envs/deuce-client/.env/bin/python3
"""
Ben's Deuce Testing Client
"""
from __future__ import print_function
import argparse
import hashlib
import json
import logging
import math
import os
import pprint
import requests
import sys
import tempfile
import uuid

import deuceclient.api as api
import deuceclient.auth.nonauth as noauth
import deuceclient.auth.openstackauth as openstackauth
import deuceclient.auth.rackspaceauth as rackspaceauth
import deuceclient.client.deuce as client
import deuceclient.utils as utils


class ProgramArgumentError(ValueError):
    pass


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
    auth_url = arguments['auth_service_url']
    auth_provider = arguments['auth_service']

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

    user_data = json.load(arguments['user_config'])
    if not find_user(user_data):
        sys.stderr.write('Unknown User Type.\n Example Config: {0:}'.format(
            example_user_config_json))
        sys.exit(-2)

    if not find_credentials(user_data):
        sys.stderr.write('Unknown Auth Type.\n Example Config: {0:}'.format(
            example_user_config_json))
        sys.exit(-3)

    # Setup the Authentication
    datacenter = arguments['datacenter']

    asp = None
    if auth_provider == 'openstack':
        asp = openstackauth.OpenStackAuthentication

    elif auth_provider == 'rackspace':
        asp = rackspaceauth.RackspaceAuthentication

    elif auth_provider == 'none':
        asp = noauth.NonAuthAuthentication

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

    return auth_engine


def get_file_hash(file_name):
    sha1 = hashlib.sha1()
    with open(file_name, 'rb') as input_data:
        while True:
            chunk = input_data.read(1024)
            if chunk:
                sha1.update(chunk)
            else:
                break
    return sha1.hexdigest().lower()


def get_file_length(file_name):
    length = 0
    with open(file_name, 'rb') as input_data:
        input_data.seek(0, os.SEEK_END)
        length = input_data.tell()
    return length


def get_file_data(file_name):
    return {
        'hash': get_file_hash(file_name),
        'length': get_file_length(file_name)
    }


def make_file(file_name, byte_count, chunking=1024 * 1024):
    with open(file_name, 'wb') as file_data:
        for _ in range(int(byte_count / chunking)):
            file_data.write(os.urandom(chunking))
        remainder = byte_count % chunking
        if remainder:
            file_data.write(os.urandom(remainder))


def main():
    arg_parser = argparse.ArgumentParser(
        description="Cloud Backup Agent Status")
    arg_parser.add_argument('--user-config',
                            default=None,
                            type=argparse.FileType('r'),
                            required=True,
                            help='JSON file containing username and API Key')

    arguments = arg_parser.parse_args()

    # If the caller provides a log configuration then use it
    # Otherwise we'll add our own little configuration as a default
    # That captures stdout and outputs to output/integration-slave-server.out
    lf = logging.FileHandler('.deuceclient_test_storage_post-py.log')
    lf.setLevel(logging.DEBUG)

    log = logging.getLogger()
    log.addHandler(lf)
    log.setLevel(logging.DEBUG)

    # Build the logger
    log = logging.getLogger()

    # Setup
    auth_arguments = {
        'auth_service_url': None,
        'auth_service': 'rackspace',
        'user_config': arguments.user_config,
        'datacenter': 'iad'
    }
    auth_engine = __api_operation_prep(log, auth_arguments)

    urls = {
        # 'cassandra': '192.168.3.1:80',
        # 'mongodb': '192.168.3.2:80',
        # 'sqlite': '192.168.3.3:80'
        'local-wsgi-ref': '127.0.0.1:8080'
    }

    print('AuthToken: {0:}'.format(auth_engine.AuthToken))
    print('TenantID: {0:}'.format(auth_engine.AuthTenantId))

    # Vault Name:
    vault_name = 'brm_test_{0:}'.format(str(uuid.uuid4()))

    for backend, url in urls.items():
        print('Testing: {0:} - {1:}'.format(backend, url))
        # Setup Agent Access
        deuceclient = client.DeuceClient(auth_engine, url)

        print('\tCreating Vault Name: {0:}'.format(vault_name))
        # Create vault
        vault = deuceclient.CreateVault(vault_name)

        data = os.urandom(100)
        storage_url = 'http://{0:}{1:}'.format(url,
            api.v1.get_storage_blocks_path(vault.vault_id))
        headers = {
            'X-Auth-Token': auth_engine.AuthToken,
            'X-Project-ID': auth_engine.AuthTenantId,
            'Content-Type': 'application/octet-stream',
            'X-Deuce-User-Agent': 'brm-tester',
            'User-Agent': 'brm-tester/1.0'
        }

        log.debug('URL: {0:}'.format(storage_url))
        log.debug('Headers: {0:}'.format(headers))
        result = requests.post(storage_url, headers=headers, data=data)
        log.debug('Result - Headers: {0:}'.format(result.headers))
        print('Result - Headers: {0:}'.format(result.headers))
        log.debug('Result - Status Code: {0:}, Text: {1:}'.format(
            result.status_code, result.text))
        print('Result - Status Code: {0:}, Text: {1:}'.format(
            result.status_code, result.text))


if __name__ == "__main__":
    sys.exit(main())

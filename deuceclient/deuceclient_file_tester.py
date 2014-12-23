#!/home/bmeyer/rackspace/envs/deuce-client/.env/bin/python3
"""
Ben's Deuce Testing Client
"""
from __future__ import print_function
import argparse
import datetime
import hashlib
import json
import logging
import math
import os
import pprint
import sys
import tempfile
import uuid

import prettytable

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
    arg_parser.add_argument('--file-name',
                            default=None,
                            type=str,
                            required=False,
                            help='Optional file to use instead of '
                            'auto-generating a file')

    arguments = arg_parser.parse_args()

    # If the caller provides a log configuration then use it
    # Otherwise we'll add our own little configuration as a default
    # That captures stdout and outputs to output/integration-slave-server.out
    lf = logging.FileHandler('.deuce_client-py.log')
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
        'remote-cassandra': '192.168.3.1:80',
        # 'public-cassandra': '104.130.4.208',
        # 'snet-cassandra': '10.208.225.101',
        # 'remote-mongodb': '192.168.3.2:80',
        # 'remote-sqlite': '192.168.3.3:80'
        # 'local-wsgi-ref': '127.0.0.1:8080'
        # 'local-wsgi-server': '127.0.0.1:8081',
        # 'local-nginx-server': '127.0.0.1:80'
    }

    # file_sizes = [X * 1024 for X in
    #              [int(math.pow(2, Y)) for Y in range(15)]]

    user_specified_file = arguments.file_name is not None

    file_sizes = [2 * 1024 * 1024 * 1024]

    if user_specified_file:
        try:
            print('Found user specified file: {0:}'.format(
                arguments.file_name))
            user_file_length = get_file_length(arguments.file_name)
            print('\tFile has {0:} bytes'.format(user_file_length))
            file_sizes = [user_file_length]
        except:
            print('\tFailed to use the user\'s file: {0:}'.format(
                arguments.file_name))
            user_specified_file = False

    print('Retrieving credentials...')
    print('\tAuthToken: {0:}'.format(auth_engine.AuthToken))
    print('\tTenantID: {0:}'.format(auth_engine.AuthTenantId))
    time_checks = {}

    def start_timer(file_size, backend, url, timer):
        if file_size not in time_checks:
            time_checks[file_size] = {}

        if backend not in time_checks[file_size]:
            time_checks[file_size][backend] = {}

        if url not in time_checks[file_size][backend]:
            time_checks[file_size][backend][url] = {}

        if timer not in time_checks[file_size][backend][url]:
            time_checks[file_size][backend][url][timer] = {}


        time_checks[file_size][backend][url][timer]['start'] = datetime.datetime.utcnow()

    def end_timer(file_size, backend, url, timer):
        time_checks[file_size][backend][url][timer]['end'] = datetime.datetime.utcnow()
        time_checks[file_size][backend][url][timer]['delta'] = time_checks[file_size][backend][url][timer]['end'] - time_checks[file_size][backend][url][timer]['start']

    for file_size in file_sizes:

        print('File Size: {0:} bytes -> {1:} kilobytes -> {2:} '
              'megabytes'.format(file_size,
                                 file_size / 1024,
                                 file_size / 1024 / 1024))

        # upload_file = 'upload_test_file_{0:}'.format(file_size)
        temp_file = tempfile.NamedTemporaryFile()
        if user_specified_file:
            upload_file = arguments.file_name
        else:
            upload_file = temp_file.name
            print('\tCreating file for upload...')
            make_file(upload_file, file_size)
            print('\tFile Created.')

        for backend, url in urls.items():
            try:
                print('\tTesting Backend: {0:}'.format(backend))
                # Setup Agent Access
                start_timer(file_size, backend, url, timer='instantiate_client')
                deuceclient = client.DeuceClient(auth_engine, url)
                end_timer(file_size, backend, url, timer='instantiate_client')

                # Vault Name:
                vault_name = 'brm_test_{0:}'.format(str(uuid.uuid4()))

                print('\t\tCreating Vault: {0:}'.format(vault_name))
                # Create vault
                start_timer(file_size, backend, url, timer='create_vault')
                vault = deuceclient.CreateVault(vault_name)
                end_timer(file_size, backend, url, timer='create_vault')

                # Get Vault Stats
                start_timer(file_size, backend, url, timer='get_vault_preupload_statistics')
                pre_upload_states = deuceclient.GetVaultStatistics(vault)
                end_timer(file_size, backend, url, timer='get_vault_preupload_statistics')
                if pre_upload_states:
                    for k in vault.statistics.keys():
                        print('\t\t{0:}:'.format(k), end='')
                        pprint.pprint(vault.statistics[k])

                # Upload File
                start_timer(file_size, backend, url, timer='create_file')
                file_id = deuceclient.CreateFile(vault)
                end_timer(file_size, backend, url, timer='create_file')

                start_timer(file_size, backend, url, timer='upload_file')
                with open(upload_file, 'rb') as upload_data:

                    file_splitter = utils.UniformSplitter(vault.project_id,
                                                          vault.vault_id,
                                                          upload_data)

                    while True:

                        block_list = vault.files[file_id]\
                            .assign_from_data_source(file_splitter,
                                                     append=True,
                                                     count=10)

                        if len(block_list):
                            assignment_list = []

                            for block, block_offset in block_list:
                                assignment_list.append((block.block_id,
                                                        block_offset))

                            blocks_to_upload = \
                                deuceclient.AssignBlocksToFile(vault,
                                                               file_id,
                                                               assignment_list)

                            if len(blocks_to_upload):
                                for block, offset in block_list:
                                    if block.block_id in blocks_to_upload:
                                        vault.blocks[block.block_id] = block

                                deuceclient.UploadBlocks(vault,
                                                         blocks_to_upload)

                        else:
                            break
                end_timer(file_size, backend, url, timer='upload_file')

                start_timer(file_size, backend, url, timer='finalize_file')
                deuceclient.FinalizeFile(vault, file_id)
                end_timer(file_size, backend, url, timer='finalize_file')

                file_url = vault.files[file_id].url

                print('\t\tUploaded File URL: {0:}'.format(file_url))

                # Get Vault Stats
                start_timer(file_size, backend, url, timer='get_vault_postupload_statistics')
                post_upload_states = deuceclient.GetVaultStatistics(vault)
                end_timer(file_size, backend, url, timer='get_vault_postupload_statistics')
                if pre_upload_states:
                    for k in vault.statistics.keys():
                        print('\t\t{0:}:'.format(k), end='')
                        pprint.pprint(vault.statistics[k])

                print('\t\tDownloading File...')

                # Download File
                download_temp_file = tempfile.NamedTemporaryFile()
                start_timer(file_size, backend, url, timer='download_file')
                deuceclient.DownloadFile(vault,
                                         file_id,
                                         download_temp_file.name)
                end_timer(file_size, backend, url, timer='download_file')

                # Checksum Files

                print('\t\tGenerating file information...')
                upload_file_data = get_file_data(upload_file)
                download_file_data = get_file_data(download_temp_file.name)
                delta_upload_download = (upload_file_data['length'] -
                                         download_file_data['length'])

                print('\t\tChecking file information')

                check_length = (upload_file_data['length'] ==
                                download_file_data['length'])
                check_hash = (upload_file_data['hash'] ==
                              download_file_data['hash'])

                if not check_length:
                    print('\t\tFile Lengths do not match - delta {0:}'
                          .format(delta_upload_download))
                    print('\t\t\tUpload Length: {0:}'
                          .format(upload_file_data['length']))
                    print('\t\t\tDownload Length: {0:}'
                          .format(download_file_data['length']))

                if not check_hash:
                    print('\t\tFile Hashes (SHA1) do not match:')
                    print('\t\t\tUpload Hash: {0:}'
                          .format(upload_file_data['hash']))
                    print('\t\t\tDownload Hash: {0:}'
                          .format(download_file_data['hash']))

                if check_hash and check_length:
                    print('\t\tFile MATCHES')

            except Exception as ex:
                print('\t\t{0:} - Failed with Exception - {1:}'
                      .format(backend, str(ex)))


    #import ipdb
    #ipdb.set_trace()

    table_columns = [
        'file size', 'backend', 'url', 'timer name', 'time'
    ]

    display_table = prettytable.PrettyTable(table_columns)
    for fs, fs_data in time_checks.items():
        for b, b_data in fs_data.items():
            for u, u_data in b_data.items():
                for t, t_data in u_data.items():
                    row = [
                        fs,
                        b,
                        u,
                        t,
                        '{0}'.format(t_data['delta'].total_seconds())
                    ]
                    display_table.add_row(row)
    print(display_table)


if __name__ == "__main__":
    sys.exit(main())

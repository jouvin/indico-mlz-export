#!/usr/bin/env python
import argparse
import os
from io import StringIO
from getpass import getpass
from pprint import PrettyPrinter

import requests
import json
import yaml
from lxml import html
from requests_oauthlib import OAuth2Session


# Default parameters for connecting to the Indico instance
scopes = ['registrants', 'read:legacy_api', 'read:user']
redirect_uri = 'https://localhost/'
target_verify = True

AUTH_PROVIDER_DEFAULT = "indico"

CONFIG_FILE_DEFAULT = '{}.cfg'.format(os.path.splitext(os.path.basename(__file__))[0])

# No modification beyond this point...

HTTP_STATUS_OK = 200
HTTP_STATUS_REDIRECTED = 302
HTTP_STATUS_FORBIDDEN = 403
HTTP_STATUS_NOT_FOUND = 404

class MissingConfigParams(Exception):
    """
    Raised when no a required parameter is missing in the configuration file
    """

    def __init__(self, param, file):
        self.msg = "Parameter '{}' is missing in the configuration file ({})".format(param, file)

    def __str__(self):
        return repr(self.msg)


def load_config_file(file):
    try:
        with open(file, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
    except:
        print('ERROR: failed to read configuration file ({})'.format(file))
        raise

    if 'client_id' not in config:
        raise MissingConfigParams('client_id', file)
    if 'client_secret' not in config:
        raise MissingConfigParams('client_secret', file)
    if 'indico_url' not in config:
        raise MissingConfigParams('indico_url', file)

    return config


def handle_url(res, **kwds):
    if res.status_code == HTTP_STATUS_REDIRECTED:
        if res.headers['Location'].startswith(redirect_uri):
            res.url = res.headers['Location']
            del res.headers['Location']
        return res
    elif res.status_code == HTTP_STATUS_OK:
        print('ERROR: userid or password incorrect')
        exit(2)
    else:
        raise Exception(f'Error connecting to Indico')


def getsession(config, username, password, auth_provider):
    indico = OAuth2Session(config['client_id'], scope=scopes, redirect_uri=redirect_uri)
    indico.verify = target_verify

    authorization_url, state = indico.authorization_url(config['authorization_base_url'])

    s = requests.Session()
    s.verify = target_verify
    res = s.get(
        authorization_url,
        headers={
            'X-CSRF-Token': '00000000-0000-0000-0000-000000000000'
        })
    if res.status_code == HTTP_STATUS_OK:
        auth_actual_url = res.url
    else:
        raise Exception(f'Failed to connect to authorization URL ({authorization_url})')

    res = s.post(
        auth_actual_url,
        data={
            '_provider': auth_provider, #whatever you use as auth providers
            'username': username,
            'password': password,
            'csrf_token': '00000000-0000-0000-0000-000000000000'
        })
    if res.status_code == HTTP_STATUS_NOT_FOUND:
        print(f'ERROR: authorization provider ({auth_provider}) not found')
        exit(1)
    elif res.status_code != HTTP_STATUS_OK:
        raise Exception(f'Failed to authenticate against {auth_actual_url}')

    tree = html.parse(StringIO(res.text))
    csrf = tree.xpath('//*[@id="csrf_token"]')[0].value

    res = s.post(
        res.url,
        data={
            '_provider': auth_provider, # what you use as auth provider
            'username': username,
            'password': password,
            'csrf_token': csrf
        },
        hooks=dict(response=handle_url))

    # Fetch the access token
    indico.fetch_token(
        config['token_url'],
        client_secret=config['client_secret'],
        authorization_response=res.url,
        verify=target_verify)
    return indico


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--auth-provider', default=AUTH_PROVIDER_DEFAULT, help=f'Indico authorization provider to use (D: {AUTH_PROVIDER_DEFAULT})')
    ap.add_argument('--config', default=CONFIG_FILE_DEFAULT, help=f'Configuration file (D: {CONFIG_FILE_DEFAULT})')
    ap.add_argument('--username', required=True, help="Indico user")
    ap.add_argument('--password', default=None, help="Indico password (if not specified, will be asked)")
    ap.add_argument('--flat', type=bool, default=False)
    ap.add_argument('--confid', type=int, default=56)
    args = ap.parse_args()

    config = load_config_file(args.config)

    if not args.password:
        args.password = getpass(prompt=f"Password for {args.username}? ")
        if len(args.password) == 0:
            raise Exception('Password must not be empty')

    # OAuth endpoints given in the GitHub API documentation
    config['authorization_base_url'] = config['indico_url'] + 'oauth/authorize'
    config['token_url'] = config['indico_url'] + 'oauth/token'

    indico = getsession(config, args.username, args.password, args.auth_provider)

    if args.flat:
        # Fetch all registrants (flattend format with ids)
        registrants_base = 'mlz/export/{.confid}/registrants_flat'.format(args)
        #registrants_base = 'api/events/{.confid}/registrants'.format(args)
    else:
        # Fetch all registrants
        registrants_base = 'mlz/export/{.confid}/registrants'.format(args)
        #registrants_base = 'api/events/{.confid}/registrants'.format(args)

    r = indico.get(config['indico_url'] + registrants_base)
    registrants = json.loads(r.content)

    pp = PrettyPrinter(indent=4)

    for r in registrants:
        registrant_base = registrants_base + '/{registrant_id}'.format(**r)
        res = indico.get(config['indico_url'] + registrant_base)
        registrant_data = json.loads(res.content)
        print(f"##### Data for participant {registrant_data['full_name']} ({registrant_data['personal_data']['affiliation']})  #####")
        pp.pprint(registrant_data)


if __name__ == '__main__':
    exit(main())
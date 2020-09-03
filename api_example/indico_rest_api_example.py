#!/usr/bin/env python
import argparse
import sys
from io import StringIO
from getpass import getpass
from pprint import PrettyPrinter

import requests
import json
from lxml import html
from requests_oauthlib import OAuth2Session

#

# Credentials you get from registering a new application
client_id = 'eee44dff-b924-497e-803b-e432d95d37ce'
client_secret = 'd3a3a448-838c-4b60-b80e-3bcff9b95bc9'

scopes = ['registrants', 'read:legacy_api', 'read:user']
redirect_uri = 'https://localhost/'

target_base = 'https://indico.ijclab.in2p3.fr/'
target_verify = True
# OAuth endpoints given in the GitHub API documentation
authorization_base_url = target_base + 'oauth/authorize'
token_url = target_base + 'oauth/token'
auth_provider = "indico"

HTTP_STATUS_OK = 200
HTTP_STATUS_REDIRECTED = 302
HTTP_STATUS_FORBIDDEN = 403
HTTP_STATUS_NOT_FOUND = 404


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


def getsession(username, password):
    indico = OAuth2Session(client_id, scope=scopes, redirect_uri=redirect_uri)
    indico.verify = target_verify

    authorization_url, state = indico.authorization_url(authorization_base_url)

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
        token_url,
        client_secret=client_secret,
        authorization_response=res.url,
        verify=target_verify)
    return indico


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--username', required=True, help="Indico user")
    ap.add_argument('--password', default=None, help="Indico password (if not specified, will be asked")
    ap.add_argument('--flat', type=bool, default=False)
    ap.add_argument('--confid', type=int, default=56)
    args = ap.parse_args()

    if not args.password:
        args.password = getpass(prompt=f"Password for {args.username}? ")
        if len(args.password) == 0:
            raise Exception('Password must not be empty')

    indico = getsession(args.username, args.password)

    if args.flat:
        # Fetch all registrants (flattend format with ids)
        registrants_base = 'mlz/export/{.confid}/registrants_flat'.format(args)
        #registrants_base = 'api/events/{.confid}/registrants'.format(args)
    else:
        # Fetch all registrants
        registrants_base = 'mlz/export/{.confid}/registrants'.format(args)
        #registrants_base = 'api/events/{.confid}/registrants'.format(args)

    r = indico.get(target_base + registrants_base)
    registrants = json.loads(r.content)

    pp = PrettyPrinter(indent=4)

    for r in registrants:
        registrant_base = registrants_base + '/{registrant_id}'.format(**r)
        res = indico.get(target_base + registrant_base)
        pp.pprint(json.loads(res.content))


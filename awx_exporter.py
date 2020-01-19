import argparse
import collections
import json
import os
import random
import re
import sys
from getpass import getpass
import pyaml
import requests
import yaml
from yaml import CLoader as Loader
from requests.auth import HTTPBasicAuth


HOST = str()
TOKEN = str()
VERIFY_SSL = True
SEPARATE_INVENTORIES = False
INV_FILE = str()
MAX_CONNECTION_ATTEMPTS = 5


def create_arg_parser():
    parser = argparse.ArgumentParser(add_help=True,
                                     description="Quick and dirty way to make a portable workstation version of your "
                                                 "awx/ansible tower inventories")
    parser.add_argument('HOST',
                        help="the fully qualified domain name of your awx/tower instance",
                        )
    parser.add_argument('TOKEN',
                        nargs='?',
                        help="an authentication token for your awx/tower instance, can be readonly",
                        default=None)
    parser.add_argument('-u',
                        '--username',
                        help='use with -p if you can\'t or won\'t use a token')
    parser.add_argument('-p', '--password', dest='password',
                        help='hidden password prompt',
                        nargs='?',
                        default=None,
                        const=True)

    parser.add_argument('-s',
                        dest='SEPARATE_INVENTORIES',
                        action="store_true",
                        help="if set, will create a separate inventory file for each one present on the awx/tower "
                             "instance, otherwise all inventories will be treated as groups and placed in the same file",
                        default=False
                        )
    parser.add_argument('-i',
                        '--inventory_file_name',
                        default='awx_hosts',
                        help="the name for the newly generated inventory file, does nothing if used with -s")
    parser.add_argument('-k',
                        dest='VERIFY_SSL',
                        action="store_false",
                        default=True,
                        help="skips ssl verification, use with caution")
    parser.add_help = True
    return parser


# currently unused
def set_local_ca_chain():
    # debian
    os.environ['REQUESTS_CA_BUNDLE'] = os.path.join(
        '/etc/ssl/certs/',
        'ca-certificates.crt')
    # centos
    #   'ca-bundle.crt')


def request_get(endpoint, select_results: bool = True, try_get_all: bool = True, ):
    auth_header = f'Bearer {TOKEN}'
    response = requests.get(url=f'{HOST + endpoint}', headers={'Authorization': auth_header}, verify=VERIFY_SSL)
    response_data = json.loads(response.content)
    if not select_results:
        return response_data
    elif try_get_all:
        response_data_collated = response_data['results']
        while response_data['next'] is not None:
            try:
                raw_response = requests.get(url=f"{HOST + response_data['next']}",
                                            headers={'Authorization': auth_header},
                                            verify=VERIFY_SSL)
                response_data = json.loads(raw_response.content)
                if isinstance(response_data_collated, list) and isinstance(response_data['results'], list):
                    response_data_collated.extend(response_data['results'])
                else:
                    response_data_collated.update(response_data['results'])
            except Exception as ex:
                print(ex)
                break
        return response_data_collated
    elif select_results:
        return response_data['results']


def request_post(endpoint, data={}):
    auth_header = f'Bearer {TOKEN}'
    response = requests.get(url=f'{HOST + endpoint}', headers={'Authorization': auth_header}, verify=VERIFY_SSL,
                            data=data)
    response_data = json.loads(response.content)
    return response_data['results']


def output_to_file(file_name, data, overwrite: bool = False, fmt: str = 'yaml'):
    # this uses pyaml just because it deals with printing null values in a nicer (read: easier for me to figure out) fashion
    if os.path.exists(file_name) and overwrite:
        print("destination file already exists, aborting")
        raise FileExistsError()
    else:
        try:
            with open(file_name, 'w') as f:
                if fmt == 'yaml':
                    print(pyaml.dump(data), file=f)
                elif fmt == 'json':
                    print(json.dumps(data), file=f)
                else:
                    raise NameError()
        except Exception as ex:
            print(ex)
            raise ex


def create_group_dict(group_list) -> dict:
    group_dict = dict()
    for group in group_list:

        ht_dict = dict()

        # get host list for group
        hg_list = dict()
        hg = request_get(f"/api/v2/groups/{group['id']}/all_hosts/")
        for group_host in hg:
            try:
                hg_list[f"{group_host['name']}"] = None
            except Exception as ex:
                pass
        ht_dict['hosts'] = hg_list
        ht_dict['vars'] = yaml.load(group['variables'], Loader=Loader)
        group_dict[f"{group['name']}"] = ht_dict
    return group_dict


def main():
    inv = dict()

    try:
        # get raw hosts
        h_all_dict = dict()
        gg = get_hosts_info()
        for h in gg:
            # ht = run_awx_cli(f"hosts get {h['id']}")
            h_all_dict[f"{h['name']}"] = yaml.load(h['variables'], Loader=Loader)
        inv['hosts'] = h_all_dict
        # end raw hosts

        # get groups
        # g_list = run_awx_cli(f"groups list --all --has_inventory_sources false")
        g_list = request_get('/api/v2/groups/')
        g_dict = create_group_dict(g_list)

        inventories = request_get(f"/api/v2/inventories/")

        # if separate_inventories is false, treat defined inventories as groups to retain defined variables
        if not SEPARATE_INVENTORIES:
            for i in inventories:
                i_dict = dict()
                i_dict['vars'] = yaml.load(i['variables'], Loader=Loader)
                i_hosts_dict = dict()
                i_hosts_data = request_get(f"/api/v2/inventories/{i['id']}/hosts")
                for ih in i_hosts_data:
                    i_hosts_dict[f"{ih['name']}"] = None
                i_dict['hosts'] = i_hosts_dict
                g_dict[f"{i['name']}"] = i_dict
        else:
            for i in inventories:
                inventory = request_get(f"/api/v2/inventories/{i['id']}/script/", select_results=False)
                inv_hosts_raw = request_get(f"/api/v2/inventories/{i['id']}/hosts/")
                h_inv_dict = dict()
                for h in inv_hosts_raw:
                    # ht = run_awx_cli(f"hosts get {h['id']}")
                    if check_group_name_compatibility(h['name']) is not None:
                        h_inv_dict[f"{check_group_name_compatibility(h['name'])}"] = yaml.load(
                            list_to_null_dict(h['variables']), Loader=Loader)
                # inventory['all']['hosts'] = h_inv_dict
                children_dict: dict = dict(map(lambda o: (o[0], list_to_null_dict(o[1])),
                                               dict(filter(lambda x: x[0] != 'all', inventory.items())).items()))
                children_dict2 = recurse_dict(children_dict)
                final_dict = {"all": {"hosts": h_inv_dict,
                                      "children": children_dict2}}

                output_to_file(file_name=i['name'], data=final_dict)

        inv['children'] = g_dict
        global_dict = dict()
        global_dict['all'] = inv

        try:
            output_to_file(INV_FILE, global_dict)
        except Exception as ex:
            print(ex)
        return global_dict
    except Exception as ex:
        print(ex)
        raise ex

    pass


def check_group_name_compatibility(group_name: str, skip_on_error: bool = True):
    r = re.compile("^(\\d)+$")  # integers only, will cause ansible to freak out
    try:
        if r.match(str(group_name)):
            print(f'{group_name} is an invalid group name, skipping')
            if skip_on_error:
                return None
            else:
                return f"invalid_group_name_{random.randint(1, 10000)}"
        else:
            return group_name
    except Exception as ex:
        print(ex)
        return group_name


def recurse_dict(input_object, func=None):
    output_object = dict()
    if isinstance(input_object, dict):
        for d in input_object:
            if func is None:
                if (p := check_group_name_compatibility(d)) is not None:
                    output_object[p] = input_object[d]
                else:
                    continue
            else:
                try:
                    (x, y) = func(d, input_object.pop(d))
                    output_object[x] = y
                except Exception as generic_ex:
                    print(generic_ex)
                    raise generic_ex
            if output_object.keys().__contains__(d) and (
                    isinstance(input_object[d], dict) or isinstance(input_object[d], list)):
                output_object[d] = recurse_dict(input_object[d])
            else:
                continue
    else:
        output_object = input_object
    return output_object


def list_to_null_dict(input_object: object):
    if isinstance(input_object, dict):
        for d in input_object:
            if isinstance(input_object[d], dict) or isinstance(input_object[d], list):
                input_object[d] = list_to_null_dict(input_object[d])
            else:
                continue
        return input_object
    elif isinstance(input_object, list):
        r_dict = dict()
        for item in input_object:
            r_dict[item] = None
        return r_dict
    elif isinstance(input_object, str):
        return check_group_name_compatibility(input_object)
    elif isinstance(input_object, int):
        return check_group_name_compatibility(str(input_object))
    else:
        return input_object


def get_hosts_info():
    hi = request_get('/api/v2/hosts/')
    return hi


def get_token_from_credentials(username, password):
    b = Base()
    return b.get_oauth2_token(username, password)


# mostly copied from awxkit
class Token_Auth(requests.auth.AuthBase):
    def __init__(self, token, auth_type='Token'):
        self.token = token
        self.auth_type = auth_type

    def __call__(self, request):
        request.headers['Authorization'] = '{0.auth_type} {0.token}'.format(self)
        return request


# mostly copied from awxkit
class Connection(object):
    def __init__(self, server, verify=False):
        self.server = server
        self.verify = verify

        if not self.verify:
            requests.packages.urllib3.disable_warnings()

        self.session = requests.Session()
        self.uses_session_cookie = False

    def get_session_requirements(self, next='/api/'):
        self.get('/api/')  # this causes a cookie w/ the CSRF token to be set
        return dict(next=next)

    def login(self, username=None, password=None, token=None, **kwargs):
        if username and password:
            _next = kwargs.get('next')
            if _next:
                headers = self.session.headers.copy()
                self.post('/api/login/', headers=headers,
                          data=dict(username=username, password=password, next=_next))
                self.session_id = self.session.cookies.get('sessionid')
                self.uses_session_cookie = True
            else:
                self.session.auth = (username, password)
        elif token:
            self.session.auth = Token_Auth(token, auth_type=kwargs.get('auth_type', 'Token'))
        else:
            self.session.auth = None

    def logout(self):
        if self.uses_session_cookie:
            self.session.cookies.pop('sessionid', None)
        else:
            self.session.auth = None

    def request(self, relative_endpoint, method='get', json=None, data=None, query_parameters=None, headers=None):
        """Core requests.Session wrapper that returns requests.Response objects"""
        session_request_method = getattr(self.session, method, None)
        if not session_request_method:
            raise Exception("Unknown request method: {0}".format(method))

        use_endpoint = relative_endpoint
        if self.server.endswith('/'):
            self.server = self.server[:-1]
        if use_endpoint.startswith('/'):
            use_endpoint = use_endpoint[1:]
        url = '/'.join([self.server, use_endpoint])

        kwargs = dict(verify=self.verify, params=query_parameters, json=json, data=data
                      )

        if headers is not None:
            kwargs['headers'] = headers

        if method in ('post', 'put', 'patch', 'delete'):
            kwargs.setdefault('headers', {})['X-CSRFToken'] = self.session.cookies.get('csrftoken')
            kwargs['headers']['Referer'] = url

        for attempt in range(1, MAX_CONNECTION_ATTEMPTS + 1):
            try:
                response = session_request_method(url, **kwargs)
                break
            except requests.exceptions.ConnectionError as err:
                if attempt == MAX_CONNECTION_ATTEMPTS:
                    raise err
                print('Failed to reach url: {0}.  Retrying.'.format(url))

        return response

    def get(self, relative_endpoint, query_parameters=None, headers=None):
        return self.request(relative_endpoint, method='get', query_parameters=query_parameters, headers=headers)

    def post(self, relative_endpoint, json=None, data=None, headers=None):
        return self.request(relative_endpoint, method='post', json=json, data=data, headers=headers)


# mostly copied from awxkit
class Base(object):
    def __init__(self):
        self.connection = Connection(HOST, VERIFY_SSL)

    def get_oauth2_token(self, a_username='', a_password='', scope='write'):

        req = collections.namedtuple('req', 'headers')({})

        HTTPBasicAuth(a_username, a_password)(req)
        resp = self.connection.post(
            '/api/v2/users/{}/personal_tokens/'.format(a_username),
            json={
                "description": "Tower CLI",
                "application": None,
                "scope": scope
            },
            headers=req.headers
        )
        if resp.ok:
            result = resp.json()
            return result.pop('token', None)
        else:
            raise Exception


if __name__ == '__main__':
    arg_parser = create_arg_parser()
    parsed_args = arg_parser.parse_args(sys.argv[1:])
    HOST = str(parsed_args.HOST).rstrip('/') + '/'  # make sure it has exactly 1 forward slash at the end
    TOKEN = parsed_args.TOKEN
    VERIFY_SSL = parsed_args.VERIFY_SSL
    if not VERIFY_SSL:
        requests.packages.urllib3.disable_warnings()
    INV_FILE = parsed_args.inventory_file_name
    SEPARATE_INVENTORIES = parsed_args.SEPARATE_INVENTORIES
    if parsed_args.TOKEN is None:
        if parsed_args.username is None or parsed_args.password is None:
            print("provide either a token or username/password to authenticate")
            raise SystemExit
        elif parsed_args.password is not None:
            if isinstance(parsed_args.password, bool):
                U_PASSWORD = getpass()
            else:
                U_PASSWORD = parsed_args.password
            try:
                TOKEN = get_token_from_credentials(parsed_args.username, U_PASSWORD)
            except Exception as ex:
                print(ex)
                raise ex
        else:
            raise SystemExit
    main()

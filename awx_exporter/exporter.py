import collections
import json
import os
import random
import re
from getpass import getpass

import pyaml
import requests
import yaml
from requests.auth import HTTPBasicAuth
from yaml import CLoader as Loader

from awx_exporter.utils import check_group_name_compatibility, recurse_dict
from awx_exporter.connection import Connection


class Exporter(object):
    def __init__(self, pre_parsed_args, defaults: dict = None):
        # set defaults, allow to be overwritten
        if defaults is not None:
            for key in defaults:
                setattr(self, key, defaults[key])

        parsed_args = pre_parsed_args
        self.Host = str(parsed_args.Host).rstrip('/') + '/'  # make sure it has exactly 1 forward slash at the end
        self.TOKEN = parsed_args.TOKEN
        self.VERIFY_SSL = parsed_args.VERIFY_SSL
        if not self.VERIFY_SSL:
            requests.packages.urllib3.disable_warnings()
        self.INV_FILE = parsed_args.inventory_file_name
        self.SEPARATE_INVENTORIES = parsed_args.SEPARATE_INVENTORIES
        self.connection = Connection(self.Host, self.VERIFY_SSL)

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
                    self.TOKEN = self.get_oauth2_token(parsed_args.username, U_PASSWORD)
                except Exception as ex:
                    print(ex)
                    raise ex
            else:
                raise SystemExit

    # currently unused
    def set_local_ca_chain(self):
        # debian
        os.environ['REQUESTS_CA_BUNDLE'] = os.path.join(
            '/etc/ssl/certs/',
            'ca-certificates.crt')
        # centos
        #   'ca-bundle.crt')

    def request_get(self, endpoint, select_results: bool = True, try_get_all: bool = True, ):
        auth_header = f'Bearer {self.TOKEN}'
        response = requests.get(url=f'{self.Host + endpoint}', headers={'Authorization': auth_header},
                                verify=self.VERIFY_SSL)
        response_data = json.loads(response.content)
        if not select_results:
            return response_data
        elif try_get_all:
            response_data_collated = response_data['results']
            while response_data['next'] is not None:
                try:
                    raw_response = requests.get(url=f"{self.Host + response_data['next']}",
                                                headers={'Authorization': auth_header},
                                                verify=self.VERIFY_SSL)
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

    def request_post(self, endpoint, data={}):
        auth_header = f'Bearer {self.TOKEN}'
        response = requests.get(url=f'{self.Host + endpoint}', headers={'Authorization': auth_header},
                                verify=self.VERIFY_SSL,
                                data=data)
        response_data = json.loads(response.content)
        return response_data['results']

    def output_to_file(self, file_name, data, overwrite: bool = False, fmt: str = 'yaml'):
        # this uses pyaml just because it deals with printing null values in a nicer (read: easier for me to figure
        # out) fashion
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

    def create_group_dict(self, group_list) -> dict:
        group_dict = dict()
        for group in group_list:

            ht_dict = dict()

            # get host list for group
            hg_list = dict()
            hg = self.request_get(f"/api/v2/groups/{group['id']}/all_hosts/")
            for group_host in hg:
                try:
                    hg_list[f"{group_host['name']}"] = None
                except Exception as ex:
                    pass
            ht_dict['hosts'] = hg_list
            ht_dict['vars'] = yaml.load(group['variables'], Loader=Loader)
            group_dict[f"{group['name']}"] = ht_dict
        return group_dict

    def run_export(self):
        inv = dict()

        try:
            # get raw hosts
            h_all_dict = dict()
            gg = self.get_hosts_info()
            for h in gg:
                # ht = run_awx_cli(f"hosts get {h['id']}")
                h_all_dict[f"{h['name']}"] = yaml.load(h['variables'], Loader=Loader)
            inv['hosts'] = h_all_dict
            # end raw hosts

            # get groups
            # g_list = run_awx_cli(f"groups list --all --has_inventory_sources false")
            g_list = self.request_get('/api/v2/groups/')
            g_dict = self.create_group_dict(g_list)

            inventories = self.request_get(f"/api/v2/inventories/")

            # if separate_inventories is false, treat defined inventories as groups to retain defined variables
            if not self.SEPARATE_INVENTORIES:
                for i in inventories:
                    i_dict = dict()
                    i_dict['vars'] = yaml.load(i['variables'], Loader=Loader)
                    i_hosts_dict = dict()
                    i_hosts_data = self.request_get(f"/api/v2/inventories/{i['id']}/hosts")
                    for ih in i_hosts_data:
                        i_hosts_dict[f"{ih['name']}"] = None
                    i_dict['hosts'] = i_hosts_dict
                    g_dict[f"{i['name']}"] = i_dict
            else:
                for i in inventories:
                    inventory = self.request_get(f"/api/v2/inventories/{i['id']}/script/", select_results=False)
                    inv_hosts_raw = self.request_get(f"/api/v2/inventories/{i['id']}/hosts/")
                    h_inv_dict = dict()
                    for h in inv_hosts_raw:
                        # ht = run_awx_cli(f"hosts get {h['id']}")
                        if self.check_group_name_compatibility(h['name']) is not None:
                            h_inv_dict[f"{self.check_group_name_compatibility(h['name'])}"] = yaml.load(
                                self.list_to_null_dict(h['variables']), Loader=Loader)
                    # inventory['all']['hosts'] = h_inv_dict
                    children_dict: dict = dict(map(lambda o: (o[0], self.list_to_null_dict(o[1])),
                                                   dict(filter(lambda x: x[0] != 'all', inventory.items())).items()))
                    children_dict2 = self.recurse_dict(children_dict)
                    final_dict = {"all": {"hosts": h_inv_dict,
                                          "children": children_dict2}}

                    self.output_to_file(file_name=i['name'], data=final_dict)

            inv['children'] = g_dict
            global_dict = dict()
            global_dict['all'] = inv

            try:
                self.output_to_file(self.INV_FILE, global_dict)
            except Exception as ex:
                print(ex)
            return global_dict
        except Exception as ex:
            print(ex)
            raise ex

        pass




    def list_to_null_dict(self, input_object: object):
        if isinstance(input_object, dict):
            for d in input_object:
                if isinstance(input_object[d], dict) or isinstance(input_object[d], list):
                    input_object[d] = self.list_to_null_dict(input_object[d])
                else:
                    continue
            return input_object
        elif isinstance(input_object, list):
            r_dict = dict()
            for item in input_object:
                r_dict[item] = None
            return r_dict
        elif isinstance(input_object, str):
            return self.check_group_name_compatibility(input_object)
        elif isinstance(input_object, int):
            return self.check_group_name_compatibility(str(input_object))
        else:
            return input_object

    def get_hosts_info(self):
        hi = self.request_get('/api/v2/hosts/')
        return hi

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

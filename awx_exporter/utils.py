import json
import os
import random
import re

from pyaml import dump


def output_to_file(file_name, data, overwrite: bool = False, fmt: str = 'yaml'):
    # this uses pyaml just because it deals with printing null values in a nicer (read: easier for me to figure
    # out) fashion
    if os.path.exists(file_name) and overwrite is False:
        print("destination file already exists, aborting")
        raise FileExistsError()
    else:
        try:
            with open(file_name, 'w') as f:
                if fmt == 'yaml':
                    print(dump(data), file=f)
                elif fmt == 'json':
                    print(json.dumps(data), file=f)
                else:
                    raise NameError()
        except Exception as ex:
            print(ex)
            raise ex


def check_group_name_compatibility(group_name: str, placeholder_value=None, skip_on_error: bool = True):
    r = re.compile("^(\\d)+$")  # integers only, will cause ansible to freak out
    try:
        if r.match(str(group_name)):
            print(f'{group_name} is an invalid group name, skipping')
            if skip_on_error:
                return None, placeholder_value
            else:
                return f"invalid_group_name_{random.randint(1, 10000)}", placeholder_value
        else:
            return group_name, placeholder_value
    except Exception as ex:
        print(ex)
        return group_name, placeholder_value


def recurse_dict(input_object, func=check_group_name_compatibility):
    """

    :param input_object:
    :param func:
    :return:
    """
    output_object = dict()
    if isinstance(input_object, dict):
        for d in input_object:
            # if func is None:
            #     if (p := check_group_name_compatibility(d)) is not None:
            #         output_object[p] = input_object[d]
            #     else:
            #         continue
            # else:
            try:
                (x, y) = func(d, input_object[d])
                if x is not None:
                    output_object[x] = y
                else:
                    continue
            except Exception as generic_ex:
                print(generic_ex)
                raise generic_ex
            if output_object.keys().__contains__(d) and (
                    isinstance(input_object[d], dict) or isinstance(input_object[d], list)):
                output_object[d] = recurse_dict(input_object[d], func)
            else:
                continue
    else:
        output_object = input_object
    return output_object


def set_local_ca_chain(self):
    # debian
    os.environ['REQUESTS_CA_BUNDLE'] = os.path.join(
        '/etc/ssl/certs/',
        'ca-certificates.crt')
    # centos
    #   'ca-bundle.crt')

import argparse
import sys

from .exporter import Exporter

config_defaults = dict(
    Host=str(),
    TOKEN=str(),
    VERIFY_SSL=True,
    SEPARATE_INVENTORIES=False,
    INV_FILE=str(),
    MAX_CONNECTION_ATTEMPTS=5,
    SHOW_TOKEN=False,
    FORCE=False
)


def create_arg_parser():
    parser = argparse.ArgumentParser(add_help=True,
                                     description="Quick and dirty way to make a portable workstation version of your "
                                                 "awx/ansible tower inventories")
    parser.add_argument('Host',
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
    parser.add_argument('-f', '--force',
                        help="overwrite existing files",
                        action='store_true')
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
                        help="the name for the newly generated inventory file, does nothing if used with -s, defaults "
                             "to awx_hosts")
    parser.add_argument('-k',
                        dest='VERIFY_SSL',
                        action="store_false",
                        default=True,
                        help="skips ssl verification, use with caution")
    parser.add_argument('--show_token',
                        help="Use in combination with username/password authentication if you want to have the "
                             "utility print the authentication token to STDOUT after obtaining it",
                        action="store_true")
    parser.add_help = True
    return parser


def main():
    parser = create_arg_parser()
    parsed_args = parser.parse_args(sys.argv[1:])
    try:
        e = Exporter(pre_parsed_args=parsed_args, defaults=config_defaults)
        e.run_export()
    except Exception as ex:
        print(ex)
#
#
# if __name__ == '__main__':
#     main()

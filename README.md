# awx_exporter
Quick and dirty way to make a workstation portable version of your awx/ansible tower inventories

## To Install
run
> pip install -U awx-exporter

or alternately
> python3 -m pip install -U awx-exporter

-----
## How to Use

Assuming your PATH is set up correctly, it should be accessible from the command line by typing awx-export

     usage: awx_export-runner.py [-h] [-u USERNAME] [-p [PASSWORD]] [-f] [-s] [-i INVENTORY_FILE_NAME]
                            [-k] [--show_token] Host [TOKEN]

    
      Quick and dirty way to make a portable workstation version of your awx/ansible tower
     inventories
    
     positional arguments:
       Host                  the fully qualified domain name of your awx/tower instance
       TOKEN                 an authentication token for your awx/tower instance, can be readonly  
       
     optional arguments:
       -h, --help            show this help message and exit
       
       -u USERNAME, --username USERNAME
                             use with -p if you can't or won't use a token
                             
       -p [PASSWORD], --password [PASSWORD]
                             hidden password prompt
                             
       -f, --force           overwrite existing files

       -s                    if set, will create a separate inventory file for each one present on
                             the awx/tower instance, otherwise all inventories will be treated as 
                             groups and placed in the same file
       
       -i INVENTORY_FILE_NAME, --inventory_file_name INVENTORY_FILE_NAME
                             the name for the newly generated inventory file, does nothing if used 
                             with -s, defaults to awx_hosts
                             
       -k                    skips ssl verification, use with caution
       
       --show_token          Use in combination with username/password authentication if you want to 
                             have the utility print the authentication token to STDOUT after obtaining it


## Authentication Methods

### Token
If you have a token already you can just provide it inline
eg:
> awx-export https://my.host.example.com MY_TOKEN

### Username/Password
If you don't have a token and can't get one or just cant be bothered, you can always authenticate with username/password.  If you use -p but don't provide the password inline you will be prompted with a (usually) hidden input
eg:
> awx-export https://my.host.example.com -u 420_blazeit_69 --password my_amazing_password
or 
> awx-export https://my.host.example.com --username 420_blazeit_69 -p
> Password:

## Usage
TODO

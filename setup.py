from setuptools import setup


from os import path
this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_descr = f.read()


setup(

    name='awx_exporter',
    version='0.2.1-beta',
    packages=['awx_exporter'],
    entry_points={
        "console_scripts": ['awx-export = awx_exporter.awx_exporter:main']
    },
    url='https://github.com/np-at/awx_exporter',
    license='GPL3',
    author='np-at',
    author_email='',
    description='cli tool to create a portable/workstation compatible version of awx/tower inventories',
    long_description=long_descr,
    long_description_content_type='text/markdown',
    install_requires=['PyYAML', 'requests'],
    python_requires='>=3.6'
)

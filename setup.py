from setuptools import setup


with open("README.md", "rb") as f:
    long_descr = f.read().decode("utf-8")


setup(

    name='awx_exporter',
    version='0.2',
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
    install_requires=['PyYAML', 'requests'],
    python_requires='>=3.5'
)

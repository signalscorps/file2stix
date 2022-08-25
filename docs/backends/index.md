# Stixify backend

After successfully executing Stixify creates the directory `stix2_extractions/` containing records of all STIX Objects extracted from reports.

In addition to storing extracted Objects as static .json files in the local filesystem, Stixify ships with Backends. I

Backends allow you to specify a running database that STIX Objects extracted by Stixify can be written to.

Each Backend ships with a default initialization script that is used to create the database schema Stixify will write to. This is executed the first time the backend is used.

Backends authentication is specified using a backend `<CONFIG>.yml`.

This configoration file is passed when running Stixify commands. For example, 

```shell
stixify --input-file tests/file_inputs/txt/input.txt --backend arangodb
```

## Local filesystem

The default backend is filesystem storage. This backend is always used.

## ArangoDB (`arangodb`)

This backend is built to support the ArangoDB community version.

To do this user should supply a config file named `arangodb.yml` with the following structure

```yml
host: # optional, default if blank: 'http://127.0.0.1:8529'
username: # optional, default if blank: root
password: # optional, default if blank: ''
```

The intialization script `arangodb.py` configures the following in the ArangoDB instance;

* 1x Database named `stixify`
* 1x Document Collection in the `stixify` Database named `stix_objects`
* 1x Edge Collection in the `stixify` Database named `stix_relationships`

Stixify stores files in each Collection as follows;

* All STIX 2.1 Objects with type `relationship` are stored in the `stix_relationships` Edge Collection
* All other STIX 2.1 Objects types are stored in `stix_objects` Document Collection.
* All `*_refs` properties are converted to custom relationship objects (not STIX Objects) and stored  in the `stix_relationships` Edge Collection



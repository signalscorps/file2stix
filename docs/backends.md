# Backends

Backends allow you to store STIX Objects in a database of your choice in addition to the local filesystem. This section of the documentation shows available backends and how to configure them.

## Backend structure

Each Backend ships with a default initialization script that is used to create the database schema file2stix will write to. This is executed the first time the backend is used.

Backends authentication is specified using a backend `<CONFIG>.yml`.

This configuration file is passed when running file2stix commands. For example, 

```shell
file2stix --input-file tests/file_inputs/txt/input.txt --backend arangodb
```

## Local filesystem

The default backend is filesystem storage.

When file2stix successfully executes and matches are detected two directories will be created;

1. `stix2_objects/`
	* `<object_type>`
		* `<object_id>`
			* `<object.json>` STIX Objects for observables detected. These are used for future runs of the script and to write Objects into other backends. In the sub-directories you will find STIX 2.1 Bundles containing individual STIX 2.1 Objects extracted.
2. `stix2_bundles/`
	* Final STIX bundles containing collections of Objects from observables extracted from reports. In the sub-directories you will find STIX 2.1 Bundles containing all STIX 2.1 Objects extracted from a report. Some examples can be seen in the `/tests/expected_reports` directory.

This backend is always used as the json files saved are used to populate other backends.

## ArangoDB (`arangodb`)

This backend is built to support the ArangoDB community version.

To do this user should supply a config file named `arangodb.yml` with the following structure

```yml
host: # optional, default if blank: 'http://127.0.0.1:8529'
username: # optional, default if blank: root
password: # optional, default if blank: ''
```

The `username` supplied must have permissions in ArangoDB to create new Databases and Collections, and write to these Collections.

An example can be seen in `/tests/backends/arangodb.yml`.

By passing the `--backend` flag, the backend will be invoked. For example;

```shell
file2stix --input-file tests/file_inputs/txt/input.txt --backend tests/backends/arangodb.yml
```

The initialisation script `/backends/arangodb/arangodb.py` checks for the following in the ArangoDB instance;

* 1x Database named `file2stix`
* 1x Document Collection in the `file2stix` Database named `stix_objects`
* 1x Edge Collection in the `file2stix` Database named `stix_relationships`

If these exist, then they script will start writing data. If they do not exist, the script will create them and then start writing data.

file2stix stores newly created json files (representing STIX 2.1 Objects) created on each script run (in `stix2_objects/`) in each ArangoDB Collection as follows;

* All STIX 2.1 Objects with type `relationship` are stored in the `stix_relationships` Edge Collection
* All other STIX 2.1 Objects types are stored in `stix_objects` Document Collection.
* All `*_ref` and `*_refs` properties are converted to custom relationship objects (not STIX Objects) and stored in the `stix_relationships` Edge Collection

file2stix only ever creates one version of an Object (with unique `id`), therefore no only one version of an Object will ever exist in the `stix_objects` and `stix_relationships` ArangoDB Collections.

## MongoDB (`mongodb`)
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

To do this user should supply a backend config file with the following structure;

```yml
backend: arangodb # specifies config is for arangodb backend
host: # optional, default if blank: 'http://127.0.0.1:8529'
username: # optional, default if blank: root
password: # optional, default if blank: ''
database_name: # optional, default if blank: 'file2stix'
document_collection_name: # optional, default if blank: 'stix_objects'
edge_collection_name: # optional, default if blank: 'stix_relationships'
```

The `username` supplied must have permissions in ArangoDB to create new Databases and Collections, and write to these Collections.

An example can be seen in `/tests/backends/arangodb.yml`.

By passing the `--backend` flag, the backend will be invoked. For example;

```shell
file2stix --input-file tests/file_inputs/txt/input.txt --backend tests/backends/arangodb.yml
```

The initialisation script `/backends/arangodb/arangodb.py` checks for the following in the ArangoDB instance;

* 1x Database (name defined in backend config file, default is `file2stix`)
* 1x Document Collection in the Database (name defined in backend config file, default is `stix_objects`)
* 1x Edge Collection in the Database (name defined in backend config file, default is `stix_relationships`)

If these exist, then they script will start writing data. If they do not exist, the script will create them and then start writing data.

file2stix stores newly created json files (representing STIX 2.1 Objects) created on each script run (in `stix2_objects/`) in each ArangoDB Collection.

file2stix only ever creates one version of an Object (with unique `id`), therefore only one version of an Object will ever exist in the Document and Edge ArangoDB Collections.

Here is how the STIX 2.1 Objects are stored in ArangoDB;

### STIX 2.1 Objects (except for Relationship SROs)

All STIX 2.1 Objects types (except for Relationship SROs) are stored in the Document Collection like so;

```json
{
	"_key": "<STIX OBJECT ID>",
	"<FULL STIX OBJECT PAYLOAD>"
}
```

Note, `<FULL STIX OBJECT PAYLOAD>` refers to the json key/values of the STIX Object. e.g.

```json
{
	"_key": "indicator--0eaa7158-bd7d-492f-b7c3-cb47f4ed85ab",
	"type": "indicator",
	"spec_version": "2.1",
	"id": "indicator--0eaa7158-bd7d-492f-b7c3-cb47f4ed85ab",
	"created": "2022-09-07T06:11:36.285448Z",
	"modified": "2022-09-07T09:27:21.741076Z",
	"name": "ipv4: 198.0.103.12:8000",
	"indicator_types": [
		"unknown"
	],
	"pattern": "[ ipv4-addr:value = '198.0.103.12' AND network-traffic:dst_port = '8000' ]",
	"pattern_type": "stix",
	"pattern_version": "2.1",
	"valid_from": "2022-09-07T06:11:36.285448Z",
	"object_marking_refs": [
		"marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
	]
}
```

### Relationship STIX 2.1 Objects

All STIX 2.1 Objects with type `relationship` are stored in the Edge Collection like so;

```json
{
	"_key": "<STIX RELATIONSHIP OBJECT ID>",
	"_from": "stix_objects/<STIX RELATIONSHIP OBJECT SOURCE_REF>",
	"_to": "stix_objects/<STIX RELATIONSHIP OBJECT TARGET_REF>",
	"<FULL STIX RELATIONSHIP OBJECT PAYLOAD>"
}
```

Note, `<FULL STIX RELATIONSHIP OBJECT PAYLOAD>` refers to the json key/values of the STIX Object. e.g.

```json
{
	"_key": "relationship--4bc6e063-2547-4f5d-8f30-fd6cca4037f7",
	"_from": "stix_objects/indicator--945df870-12cd-4e28-a90a-46fb6918278c",
	"_to": "stix_objects/report--b5d4d317-510f-4413-8d88-388e46cfa18b",
	"type": "relationship",
	"spec_version": "2.1",
	"id": "relationship--4bc6e063-2547-4f5d-8f30-fd6cca4037f7",
	"created": "2022-09-07T09:28:24.077169Z",
	"modified": "2022-09-07T09:28:24.077169Z",
	"relationship_type": "default-extract-from",
	"source_ref": "indicator--945df870-12cd-4e28-a90a-46fb6918278c",
	"target_ref": "report--b5d4d317-510f-4413-8d88-388e46cfa18b",
	"object_marking_refs": [
		"marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
	]
}
```

### `*_ref` and `*_refs` properties

All `*_ref` and `*_refs` properties are converted to custom relationship objects (not STIX Objects) and stored in the `stix_relationships` Edge Collection

```json
{
	"_key": "<OBJECT WITH REF PROPERTY>+<OBJECT BEING REFERENCED>",
	"_from": "stix_objects/<OBJECT WITH REF PROPERTY>",
	"_to": "stix_objects/<OBJECT BEING REFERENCED>",
	"type": "embedded-relationship",
	"relationship_description": "<PROPERTY NAME>"
}
```

For example;

```json
{
	"_key": "report--b5d4d317-510f-4413-8d88-388e46cfa18b+indicator--945df870-12cd-4e28-a90a-46fb6918278c",
	"_from": "stix_objects/report--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcb3",
	"_to": "stix_objects/indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2",
	"type": "embedded-relationship",
	"relationship_description": "object_refs"
}
```

## MongoDB (`mongodb`)

This backend is built to support the MongoDB community server.

To do this user should supply a backend config file with the following structure;

```yml
backend: mongodb # specifies config is for mongodb backend
host: # optional, default if blank: 'http://127.0.0.1:27017'
username: # optional, default if blank: ''
password: # optional, default if blank: ''
database_name: # optional, default if blank: 'file2stix'
collection_name: # optional, default if blank: 'stix_objects'
```

The `username` supplied must have permissions in MongoDB to create new Databases and Collections.

An example can be seen in `/tests/backends/mongodb.yml`.

By passing the `--backend` flag, the backend will be invoked. For example;

```shell
file2stix --input-file tests/file_inputs/txt/input.txt --backend tests/backends/mongodb.yml
```

The initialisation script `/backends/arangodb/arangodb.py` checks for the following in the ArangoDB instance;

* 1x Database (name defined in backend config file, default is `file2stix`)
* 1x Collection in the Database (name defined in backend config file, default is `stix_objects`)

If these exist, then they script will start writing data. If they do not exist, the script will create them and then start writing data.

file2stix stores newly created json files (representing STIX 2.1 Objects) created on each script run (in `stix2_objects/`) in the `stix_objects` Collection.

file2stix only ever creates one version of an Object (with unique `id`), therefore no only one version of an Object will ever exist in the `stix_objects` and `stix_relationships` ArangoDB Collections.
# file2stix Documentation

## Overview

In short; cve2stix processes inputs (files). From inputs, obeserable types are extracted. Observable types are converted to STIX 2.1 Objects.

In this documentation you will find each of these steps between input and output explained.

For installation, [please see the README.md file at the root of file2stix](https://github.com/signalscorps/file2stix).

## What's in the docs?

* [Inputs](inputs.md): You can upload a range of filetypes to file2stix. This section of the documentation explains the types of files you can upload and how they are processed before extraction happens.
* [Extractions](extractions.md): file2stix extracts observables from text and translates them into STIX 2.1 Objects. This section of the documentation describes the templates of the STIX Objects created.
* [Backends](backends.md): Backends allow you to store STIX Objects in a database of your choice in addition to the local filesystem. This section of the documentation shows available backends and how to configure them.
* [Developers / Testing](developers.md): file2stix was built to be extended. This section of the documentation covers information that will be useful to developers.

## Building these docs

You are probably reading this online (deployed via Github pages `.github/workflows/docs.yml`.

If you want to build the docs locally, from the root directory run;

```shell
pip3 install -r docs/requirements.txt
mkdocs serve --config-file mkdocs.yml
```
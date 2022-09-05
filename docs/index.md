# file2stix Documentation

In short; cve2stix processes inputs (files). From inputs, obeserable types are extracted. Observable types are converted to STIX 2.1 Objects.

In this documentation you will find each of these steps between input and output explained. 

* [Inputs](inputs.md): You can upload a range of filetypes to file2stix. This section of the documentation explains the types of files you can upload and how they are processed before extraction happens.
* [Extractions / Conversion to STIX 2.1](extractions.md): file2stix extracts observables from text and translates them into STIX 2.1 Objects. This section of the documentation describes the templates of the STIX Objects created.
* [Whitelists](whitelists.md): Default whitelists identify potentially benign file2stix extractions. This section of the documentation explains how default whitelists work and how write your own custom whitelists.
* [Backends](backends.md): Backends allow you to store STIX Objects in a database of your choice in addition to the local filesystem. This section of the documentation shows available backends and how to configure them.
* [Developers](developers.md): file2stix was built to be extended. This section of the documentation covers information that will be useful to developers.
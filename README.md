# Obstracts CLI

Obstracts CLI is your automated threat intelligence analyst.

Use Obstracts CLI to extract machine readable intelligence from unstructured data.

A project from the Signals Corps: https://www.signalscorps.com/ 


## Instructions

Download

```
git clone https://github.com/signalscorps/obstracts-cli
cd obstracts-cli
```

Setup virtual environment

```
python -m venv obstracts-cli
source obstracts-cli/bin/activate
```

Install dependencies

```
pip install -r requirements.txt
```

Run program

```
python main.py examples/input.txt
```

Creates two directories

* `stix2_extractions/`
	* STIX Objects for observables detected. These are used for future runs of the script
* `stix2_reports/`
	* Final STIX bundles containing collections of Objects from observables extracted from reports

## Updating STIX Objects

If the script detects an already extracted observable value present in `stix2_extractions/` then the `modified` time of this object is updated to the new extraction time and the updated object used in the final bundle for the report.

For example, if 1.1.1.1 detected in report 1 it would create a new object (object 1) where `created` and `modified` times were equal. Subsequently if 1.1.1.1 detected in report 2 it would use object 1 in the final bundle, but object 1 would also be updated with new `modifed` time to represent second sighting. The old bundle would remain unchanged. So bundle for report 1 would still have created and modified times equal, but report 2 would have the updated object, and so on.

## Viewer

Need a graphical STIX Bundle Viewer? Load bundles produced for your report using STIX View: https://github.com/traut/stixview

## Obstracts Web

Need more? Check out: https://www.obstracts.com/

## License

[LICENSE](/LICENSE)

## Support

Ask us anything on Discord: https://discord.gg/Qf4nmyJjME
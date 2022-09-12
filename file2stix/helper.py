"""
Bunch of helper methods
"""

import json
import yaml
from bs4 import BeautifulSoup


def inheritors(klass):
    """
    Get all inheritors of a class
    """
    # It's inefficient to use list below, but we want the order of classes
    # to be predictable. For less than 100 classes, this implementation
    # should be okay
    subclasses = list()
    # subclasses = set()
    work = [klass]
    while work:
        parent = work.pop()
        for child in parent.__subclasses__():
            if child not in subclasses:
                subclasses.append(child)
                # subclasses.add(child)
                work.append(child)
    return subclasses


def nested_dict_values(d):
    """
    Get all values in a nested dictionary
    """
    if isinstance(d, list):
        for item in d:
            yield from nested_dict_values(item)
    else:
        for v in d.values():
            if isinstance(v, dict):
                yield from nested_dict_values(v)
            else:
                yield v


def recursive_items(dictionary):
    """
    Iterate recursively over all key value pairs of dict
    """
    for key, value in dictionary.items():
        if type(value) is dict:
            yield from recursive_items(value)
        else:
            yield (key, value)


def check_false_positive_domain(domain):
    """
    At times validators module misidentifies file names
    to be domains. This function will catch some such
    mis-identifications
    """
    known_file_extensions = [
        "bat",
        "bin",
        "bmp",
        "cer",
        "cmd",
        "chm",
        "dll",
        "doc",
        "docx",
        "exe",
        "gif",
        "jpg",
        "js",
        "log",
        "p7s",
        "pdf",
        "php",
        "ppt",
        "pptx",
        "rar",
        "swf",
        "sys",
        "tmp",
        "txt",
        "vbs",
        "xls",
        "xlsx",
        "zip",
        "msg",
        "lnk",
        "odt",
        "inf",
        "msi",
        "java",
        "class",
        "jar",
        "apk",
        "app",
        "wsf",
        "gadget",
        "cgi",
        "swf",
        "js",
        "py",
        "crx",
        "plugin",
        "flv",
        "m4v",
        "mov",
        "mp4",
        "mpg",
        "swf",
        "wmv",
        "bmp",
        "gif",
        "jpg",
        "png",
        "psd",
        "svg",
        "tif",
        "tiff",
        "7z",
        "deb",
        "rpm",
        "tar",
        "gz",
        "tgz",
        "zip",
        "zipx",
        "cab",
        "vir",
        "so",
        "pf",
    ]

    file_extension = domain.split(".")[-1]

    if file_extension in known_file_extensions:
        return False
    else:
        return True


def get_text_from_xml(input_file_path):
    """
    Extracts only text content from the xml document
    """
    with open(input_file_path, "r") as f:
        soup = BeautifulSoup(f, "xml")

    text_list = soup.find_all(text=True)
    return "".join(text_list)


def get_text_from_html(input_file_path):
    """
    Extracts only text content from the xml document
    """
    with open(input_file_path, "r") as f:
        soup = BeautifulSoup(f, "html.parser")

    text_list = soup.find_all(text=True)
    return "".join(text_list)


def get_text_from_json(input_file_path):
    with open(input_file_path, "r") as f:
        data = json.load(f)

    values = list(nested_dict_values(data))
    return "\n".join([str(value) for value in values])


def get_text_from_markdown(input_file_path):
    with open(input_file_path, "r") as f:
        soup = BeautifulSoup(f, "lxml")

    text_list = soup.find_all(text=True)
    return "".join(text_list)


def get_text_from_yaml(input_file_path):
    with open(input_file_path) as f:
        data = yaml.safe_load(f)
    
    keys = []
    for key, value in recursive_items(data):
        keys.append(key)

    return "\n".join([str(key) for key in keys])


def update_stix_object(stix_object, **kwargs):
    """
    Update stix object without creating a new version
    (It's essentially cloning the stix_object with required updates)

    Below approach seems hacky, but works :)
    """
    stix_object_properties_string = stix_object.serialize()
    stix_object_properties = json.loads(stix_object_properties_string)
    for key, value in kwargs.items():
        stix_object_properties[key] = value

    stix_definition = type(stix_object)
    updated_stix_object = stix_definition(**stix_object_properties)
    return updated_stix_object

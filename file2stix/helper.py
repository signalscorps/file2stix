"""
Bunch of helper methods
"""

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

    file_name, file_extension = domain.split(".")

    if file_extension in known_file_extensions:
        return False
    else:
        return True
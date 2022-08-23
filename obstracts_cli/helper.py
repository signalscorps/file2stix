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
"""
Contains logic for extracting observables.
"""


class ExtractStixObservables:
    """
    Iterable that extracts all the observables matching a given format.
    In each iteration, it returns the next extracted observable as a STIX object..
    """

    def __init__(self, observable, text):
        self.index = 0
        self.extracted_observables = observable.extract_observables_from_text(text)

    def __iter__(self):
        return self

    def __next__(self):
        if self.index < len(self.extracted_observables):
            extracted_observable = self.extracted_observables[self.index]
            self.index += 1
            return extracted_observable.get_sdo_object()
        raise StopIteration

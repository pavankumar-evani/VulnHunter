"""Parse XML that came from outside Quanta (an uploaded rulebase, a manifest, a vendor API response).

The standard library parser expands entities, so a small document can be written to consume gigabytes of memory
(entity expansion) or to read local files in parsers that resolve external entities. Real documents of the kinds Quanta reads
have no need for entity declarations, so they are refused before parsing. A DOCTYPE that only names a DTD is allowed:
ElementTree never fetches it, and real JaCoCo and Qualys files carry one.
"""
import re
import xml.etree.ElementTree as ET  # nosec B405 - the only parse path is fromstring() below, which refuses entity declarations first

ParseError = ET.ParseError
_UNSAFE = re.compile(r"<!ENTITY|<!DOCTYPE[^>]*\[", re.I)


class UnsafeXml(ValueError):
    """The document declares entities or an internal DTD subset."""


def fromstring(text):
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    if _UNSAFE.search(text):
        raise UnsafeXml("Entity declarations and internal DTD subsets are not accepted.")
    return ET.fromstring(text)  # nosec B314 - entity declarations refused above


from .log import logger

# Keys that should NOT be parsed into lists
SINGLE_VALUE_KEYS = {
    "domain", "created", "last-modified", "reason",
}

IGNORED_KEYS = {
    "remarks", "admin-c", "tech-c", "zone-c",
    "mnt-by", "source", "notify",
}

KEY_ORDER = [
    "domain",
    "descr",
    "nserver",
    "old-ds-rdata",
    "ds-rdata",
    "created",
    "last-modified",
    "reason",
]


def parse_rpsl_objects(fh):
    """Yield parsed objects"""
    buffer = []
    for line in fh:
        if line == '\n':
            if buffer:
                yield parse_rpsl_object(buffer)
                buffer = []
        elif line.startswith(('#', '%')):
            if line.startswith('%ERROR'):
                logger.error(line.strip())
                return
        elif line.startswith(('+', '\t', ' ')):
            buffer[-1] += line[1:].lstrip()
        else:
            buffer.append(line)
    # at the end of the file, yield the last object if there's one
    if buffer:
        yield parse_rpsl_object(buffer)


def parse_rpsl_object(buffer):
    name, _, value = buffer[0].partition(':')
    obj = {
        "domain": value.strip(),
    }
    for line in buffer:
        name, _, value = line.partition(':')
        value = value.strip()
        if name in IGNORED_KEYS:
            continue
        if name in SINGLE_VALUE_KEYS:
            obj[name] = value
        elif name in obj:
            obj[name].append(value)
        else:
            obj[name] = [value, ]
    return obj


def write_rpsl_object(obj):
    buf = []
    keys = [k for k in KEY_ORDER if k in obj]
    keys.extend(set(obj) - set(keys))
    for k in keys:
        if isinstance(obj[k], list):
            values = obj[k]
        else:
            values = [obj[k], ]
        for v in values:
            buf.append("{:15} {}".format(k + ":", v))
    buf.append("")
    return "\n".join(buf)

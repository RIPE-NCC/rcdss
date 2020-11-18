
from .log import logger


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
        "nserver": [],
        "ds-rdata": [],
    }
    for line in buffer:
        name, _, value = line.partition(':')
        value = value.strip()
        if name == "nserver":
            obj["nserver"].append(value)
        elif name == "ds-rdata":
            obj["ds-rdata"].append(value)
        elif name == "last-modified":
            obj["last-modified"] = value
    return obj


def write_rpsl_object(obj):
    buf = []
    fmt = "{:15} {}"
    buf.append(fmt.format("domain:", obj.get("domain")))
    for ns in obj.get("nserver", []):
        buf.append(fmt.format("nserver:", ns))
    for ds in obj.get("old-ds-rdata", []):
        buf.append(fmt.format("old-ds-rdata:", ds))
    for ds in obj.get("ds-rdata", []):
        buf.append(fmt.format("ds-rdata:", ds))
    buf.append(fmt.format("last-modified:", obj.get("last-modified")))
    if "reason" in obj:
        buf.append(fmt.format("reason:", obj.get("reason")))
    buf.append("")
    return "\n".join(buf)

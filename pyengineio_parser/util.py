def try_convert(value, to_type, default=None):
    try:
        return to_type(value)
    except:
        return default


def byte_length(string, encoding='utf8'):
    return len(string.encode(encoding))

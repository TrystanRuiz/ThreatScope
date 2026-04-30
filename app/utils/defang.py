import re

def defang_url(value: str) -> str:
    value = re.sub(r"https?://", lambda m: m.group().replace("://", "[://]"), value)
    value = value.replace("http", "hxxp")
    return defang_domain(value)

def defang_domain(value: str) -> str:
    return re.sub(r"\.", "[.]", value)

def defang_ip(value: str) -> str:
    return re.sub(r"\.", "[.]", value)

def defang_text(value: str) -> str:
    url_pattern = re.compile(r"https?://[^\s]+")
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    domain_pattern = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|co|ru|cn|info|biz|xyz|top|club|online|site|tech|gov|edu)\b")

    value = url_pattern.sub(lambda m: defang_url(m.group()), value)
    value = ip_pattern.sub(lambda m: defang_ip(m.group()), value)
    value = domain_pattern.sub(lambda m: defang_domain(m.group()), value)
    return value

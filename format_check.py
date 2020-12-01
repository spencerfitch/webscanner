# check for bad formats and missing fields in the result.
import json

def is_number(v):
    return type(v) == int or type(v) == float

def is_bool(v):
    return type(v) == bool

def is_non_empty_string(v):
    return type(v) == str and len(v.strip()) > 0

def is_list(each_element=lambda v: True):
    def f(v):
        if type(v) != list:
            return False
        return all(each_element(i) for i in v)
    return f

def is_one_of(*args):
    def f(v):
        return any(arg == v for arg in args)
    return f

def is_range(v):
    if not is_list(each_element=is_number)(v):
        return False
    if len(v) != 2:
        return False
    return v[0] <= v[1]

# besides the format below, each element may also be a None (JSON null) for N/A situations.
fields_format = {
    "scan_time": is_number,
    "ipv4_addresses": is_list(each_element=is_non_empty_string),
    "ipv6_addresses": is_list(each_element=is_non_empty_string),
    "http_server": is_non_empty_string,
    "insecure_http": is_bool,
    "redirect_to_https": is_bool,
    "hsts": is_bool,
    "tls_versions": is_list(each_element=is_one_of("SSLv2","SSLv3","TLSv1.0","TLSv1.1","TLSv1.2","TLSv1.3")),
    "root_ca": is_non_empty_string,
    "rdns_names": is_list(each_element=is_non_empty_string),
    "rtt_range": is_range,
    "geo_locations": is_list(each_element=is_non_empty_string)
}

def check_file(filename: str) -> bool:
    with open(filename, "r") as f:
        data = json.load(f)

    if type(data) != dict:
        print("[ERROR] The entire JSON should be a dict!")
        return False
    if len(data) == 0:
        print("[ERROR] The result is empty!")
        return False

    for url, v in data.items():
        if type(v) != dict:
            print("[ERROR] Expecting the scan results (a dict) for '%s', got a %s." % (url, type(v)))
            return False

        missing_fields = set(fields_format)
        for field, value in v.items():
            if field not in fields_format.keys():
                print("[ERROR] Invalid field name (%s) in '%s'. Is it a typo?" % (field, url))
                return False
            if (value is not None) and (not fields_format[field](value)):
                print("[ERROR] Invalid value for '%s' in '%s'." % (field, url))
                return False
            missing_fields.remove(field)

        if len(missing_fields) > 0:
            print("[WARNING] The field(s) %s is/are missing for '%s'." % (missing_fields, url))
    
    return True

if __name__ == "__main__":
    import sys
    _, filename = sys.argv
    if check_file(filename):
        print("No errors were detected.")
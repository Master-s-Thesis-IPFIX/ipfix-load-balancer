import random
import socket
import struct
from numbers import Number
from typing import Tuple, TypedDict

print_debug = False


def extract_yaf_dns_info(data) -> Tuple[str, Number]:
    if "subTemplateMultiList" in data:
        stml = data["subTemplateMultiList"]
        for entry in stml:
            for record in entry:
                if "subTemplateList" in record:
                    stl = record["subTemplateList"]
                    for dns_record in stl:
                        if "dnsName" in dns_record:
                            dns_name = dns_record["dnsName"]
                            query_type = dns_record["dnsRRType"]
                            dns_query_response = dns_record["dnsQueryResponse"]
                            if dns_query_response == 1:
                                if print_debug:
                                    print("Response with type " + str(query_type) + " and name " + dns_name)
                                dns_response_list = dns_record["subTemplateList"]
                                for dns_response in dns_response_list:
                                    if query_type == 1:
                                        if print_debug:
                                            print(dns_response["sourceIPv4Address"])
                                    if query_type == 28:
                                        if print_debug:
                                            print(dns_response["sourceIPv6Address"])
                            else:
                                if print_debug:
                                    print("Query with type " + str(query_type) + " and name " + dns_name)
                                return dns_name, 4 if query_type == 1 else 6
    return "", 0


class Config(TypedDict):
    malfix_instances: int
    malfix_host: str
    malfix_base_port: int
    malfix_protocol: str
    listen_host: str
    listen_port: int
    listen_protocol: str
    benchmark: bool
    max_flows: int
    malicious_percentage: float
    dns_percentage: float
    malicious_types: list[str]
    minimal_log: bool


def get_random_dns_name():
    return ''.join(
        random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=random.randint(1, 20))) + random.choice(
        ['.com.', '.net.', '.org.', '.io.', '.dev.'])


def get_random_ipv4():
    return socket.inet_ntoa(
        struct.pack('>I', random.randint(1, 0xffffffff)))


def get_random_ipv6():
    return ':'.join(f'{random.randint(0, 0xffff):x}' for _ in range(8))

from typing import TypedDict, Optional


class IPFIXData(TypedDict):
    dnsName: Optional[str]
    dnsType: Optional[int]
    sourceIPv4Address: Optional[str]
    destinationIPv4Address: Optional[str]
    sourceIPv6Address: Optional[str]
    destinationIPv6Address: Optional[str]
    destinationTransportPort: int
    sourceTransportPort: int
    protocolIdentifier: int


malicious_dns: list[IPFIXData] = [
    # dns_tunneling_service
    {
        "dnsName": "packetriot.net.",
        "dnsType": 4,
        "sourceIPv4Address": "172.221.121.1",
        "destinationIPv4Address": "1.1.1.1",
        "sourceIPv6Address": None,
        "destinationIPv6Address": None,
        "destinationTransportPort": 53,
        "sourceTransportPort": 4313,
        "protocolIdentifier": 17
    },
    # apt_bitter
    {
        "dnsName": "tvnservereventlog.net.",
        "dnsType": 4,
        "sourceIPv4Address": "5.100.33.1",
        "destinationIPv4Address": "1.0.0.1",
        "sourceIPv6Address": None,
        "destinationIPv6Address": None,
        "destinationTransportPort": 53,
        "sourceTransportPort": 5000,
        "protocolIdentifier": 17
    }, {
        "dnsName": "whitelilyshop.com.",
        "dnsType": 4,
        "sourceIPv4Address": "172.221.121.1",
        "destinationIPv4Address": "1.1.1.1",
        "sourceIPv6Address": None,
        "destinationIPv6Address": None,
        "destinationTransportPort": 53,
        "sourceTransportPort": 4321,
        "protocolIdentifier": 17
    }, {
        "dnsName": "farleysmxpph.com.",
        "dnsType": 4,
        "sourceIPv4Address": "172.221.121.1",
        "destinationIPv4Address": "8.8.8.8",
        "sourceIPv6Address": "fe80::a1a4:886b:1b26:c90f",
        "destinationIPv6Address": "fe80::69a5:40b0:2b5b:ba24",
        "destinationTransportPort": 53,
        "sourceTransportPort": 4380,
        "protocolIdentifier": 17
    }, {
        "dnsName": "lcpcstudiover.com.",
        "dnsType": 4,
        "sourceIPv4Address": "172.221.121.1",
        "destinationIPv4Address": "8.4.4.8",
        "sourceIPv6Address": None,
        "destinationIPv6Address": None,
        "destinationTransportPort": 53,
        "sourceTransportPort": 4313,
        "protocolIdentifier": 17
    },
]
# random.shuffle(malicious_dns)

malicious_ip: list[IPFIXData] = [
    # apt_bitter
    {
        "dnsName": None,
        "dnsType": None,
        "sourceIPv4Address": "233.2.3.42",
        "destinationIPv4Address": "116.172.130.191",
        "sourceIPv6Address": None,
        "destinationIPv6Address": None,
        "destinationTransportPort": 52993,
        "sourceTransportPort": 4313,
        "protocolIdentifier": 17
    },
    # osx_pua
    {
        "dnsName": None,
        "dnsType": None,
        "sourceIPv4Address": "3.6.115.182",
        "destinationIPv4Address": "115.159.205.208",
        "sourceIPv6Address": None,
        "destinationIPv6Address": None,
        "destinationTransportPort": 14904,
        "sourceTransportPort": 4313,
        "protocolIdentifier": 17
    },
    # android_gplayed
    {
        "dnsName": None,
        "dnsType": None,
        "sourceIPv4Address": "115.236.135.4",
        "destinationIPv4Address": "172.110.10.171",
        "sourceIPv6Address": None,
        "destinationIPv6Address": None,
        "destinationTransportPort": 85,
        "sourceTransportPort": 6372,
        "protocolIdentifier": 6
    },
    # onion
    {
        "dnsName": None,
        "dnsType": None,
        "sourceIPv4Address": "173.212.254.192",
        "destinationIPv4Address": "116.204.171.29",
        "sourceIPv6Address": None,
        "destinationIPv6Address": None,
        "destinationTransportPort": 52993,
        "sourceTransportPort": 31337,
        "protocolIdentifier": 17
    },
    # woof
    {
        "dnsName": None,
        "dnsType": None,
        "sourceIPv4Address": "116.255.187.146",
        "destinationIPv4Address": "5.101.40.74",
        "sourceIPv6Address": None,
        "destinationIPv6Address": None,
        "destinationTransportPort": 80,
        "sourceTransportPort": 4000,
        "protocolIdentifier": 6
    },
]
# random.shuffle(malicious_ip)

normal: list[IPFIXData] = [
    {
        "dnsName": "google.com.",
        "dnsType": 4,
        "sourceIPv4Address": None,
        "destinationIPv4Address": None,
        "sourceIPv6Address": "fe80::a1a4:886b:1b26:c90f",
        "destinationIPv6Address": "fe80::69a5:40b0:2b5b:ba24",
        "destinationTransportPort": 53,
        "sourceTransportPort": 4313,
        "protocolIdentifier": 17
    },
    {
        "dnsName": "example.com.",
        "dnsType": 1,
        "sourceIPv4Address": "192.168.1.2",
        "destinationIPv4Address": "192.168.1.1",
        "sourceIPv6Address": None,
        "destinationIPv6Address": None,
        "destinationTransportPort": 53,
        "sourceTransportPort": 54321,
        "protocolIdentifier": 6
    },
    {
        "dnsName": None,
        "dnsType": None,
        "sourceIPv4Address": "10.0.0.1",
        "destinationIPv4Address": "10.0.0.2",
        "sourceIPv6Address": None,
        "destinationIPv6Address": None,
        "destinationTransportPort": 443,
        "sourceTransportPort": 12345,
        "protocolIdentifier": 6
    },
    {
        "dnsName": "uni-tuebingen.de.",
        "dnsType": 4,
        "sourceIPv4Address": None,
        "destinationIPv4Address": None,
        "sourceIPv6Address": "fe80::1234:5678:abcd:ef12",
        "destinationIPv6Address": "fe80::abcd:1234:5678:ef12",
        "destinationTransportPort": 53,
        "sourceTransportPort": 4321,
        "protocolIdentifier": 17
    },
    {
        "dnsName": None,
        "dnsType": None,
        "sourceIPv4Address": "172.16.0.1",
        "destinationIPv4Address": "172.16.0.2",
        "sourceIPv6Address": None,
        "destinationIPv6Address": None,
        "destinationTransportPort": 22,
        "sourceTransportPort": 2222,
        "protocolIdentifier": 6
    },
    {
        "dnsName": "yahoo.com.",
        "dnsType": 1,
        "sourceIPv4Address": "192.168.0.10",
        "destinationIPv4Address": "192.168.0.11",
        "sourceIPv6Address": None,
        "destinationIPv6Address": None,
        "destinationTransportPort": 80,
        "sourceTransportPort": 56789,
        "protocolIdentifier": 6
    },
    {
        "dnsName": None,
        "dnsType": None,
        "sourceIPv4Address": "10.1.1.1",
        "destinationIPv4Address": "10.1.1.2",
        "sourceIPv6Address": None,
        "destinationIPv6Address": None,
        "destinationTransportPort": 21,
        "sourceTransportPort": 2121,
        "protocolIdentifier": 6
    },
    {
        "dnsName": "microsoft.com.",
        "dnsType": 1,
        "sourceIPv4Address": None,
        "destinationIPv4Address": None,
        "sourceIPv6Address": "fe80::4321:8765:abcd:dcba",
        "destinationIPv6Address": "fe80::abcd:8765:4321:dcba",
        "destinationTransportPort": 53,
        "sourceTransportPort": 9876,
        "protocolIdentifier": 17
    },
    {
        "dnsName": None,
        "dnsType": None,
        "sourceIPv4Address": "192.168.100.1",
        "destinationIPv4Address": "192.168.100.2",
        "sourceIPv6Address": None,
        "destinationIPv6Address": None,
        "destinationTransportPort": 3389,
        "sourceTransportPort": 1024,
        "protocolIdentifier": 6
    },
    {
        "dnsName": "apple.com.",
        "dnsType": 4,
        "sourceIPv4Address": None,
        "destinationIPv4Address": None,
        "sourceIPv6Address": "fe80::5678:1234:abcd:ef90",
        "destinationIPv6Address": "fe80::abcd:5678:1234:ef90",
        "destinationTransportPort": 53,
        "sourceTransportPort": 8765,
        "protocolIdentifier": 17
    }
]
# random.shuffle(normal)

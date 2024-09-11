import random

malicious_dns: list = [
    {
        "type": "dns",
        "dnsName": "packetriot.net.",
        "dnsType": 4
    }, {
        "type": "dns",
        "dnsName": "tvnservereventlog.net.",
        "dnsType": 4
    }, {
        "type": "dns",
        "dnsName": "whitelilyshop.com.",
        "dnsType": 4
    }, {
        "type": "dns",
        "dnsName": "farleysmxpph.com.",
        "dnsType": 4
    }, {
        "type": "dns",
        "dnsName": "lcpcstudiover.com.",
        "dnsType": 4
    },
]
random.shuffle(malicious_dns)

malicious_ip: list = [
    # apt_bitter
    {
        "type": "ip",
        "destinationIPv4Address": "5.101.40.74",
        "destinationTransportPort": 80,
    },
    # osx_pua
    {
        "type": "ip",
        "destinationIPv4Address": "45.95.146.93",
        "destinationTransportPort": 82,
    },
    # android_gplayed
    {
        "type": "ip",
        "destinationIPv4Address": "172.110.10.171",
        "destinationTransportPort": 85,
    },
    # onion
    {
        "type": "ip",
        "destinationIPv4Address": "185.132.125.193",
        "destinationTransportPort": 81,
    },
    # woof
    {
        "type": "ip",
        "destinationIPv4Address": "5.101.40.74",
        "destinationTransportPort": 80,
    },
]
random.shuffle(malicious_ip)

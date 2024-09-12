import random
import statistics
import time
from typing import Optional

import pyfixbuf
import pyfixbuf.cert
from numpy.random import choice

import benchmark_data
from FixReceiver import FixReceiver
from FixSender import FixSender
from helper import Config, get_random_ipv4, get_random_ipv6
from random_dns_dict import random_dns


class IPFIXLoadBalancer:
    def __init__(self, import_elements: list, export_elements: list, config: Config):
        self._import_elements: list = import_elements
        self._export_elements: list = export_elements

        self._receiver: Optional[FixReceiver] = None
        self._sender: list[FixSender] = []

        self._record: Optional[pyfixbuf.Record] = None
        self._benchmark_records: list[pyfixbuf.Record] = []

        self._current_sender: int = 0

        self._last_report_time = time.time()
        self._delta_packet_count = 0
        self._total_packet_count = 0
        self.config = config

        self._packets_per_second: list[float] = []

        self._malicious_benchmark_data = (
            [item for pair in zip(benchmark_data.malicious_dns, benchmark_data.malicious_ip) for item in pair]
            if "dns" in config['malicious_types'] and "ip" in config['malicious_types']
            else benchmark_data.malicious_dns
            if "dns" in config['malicious_types']
            else benchmark_data.malicious_ip)

    def setup(self):
        infomodel = pyfixbuf.InfoModel()
        pyfixbuf.cert.add_elements_to_model(infomodel)
        infomodel.add_element(pyfixbuf.InfoElement('dnsName', 420, 1, type=pyfixbuf.DataType.STRING))
        infomodel.add_element(pyfixbuf.InfoElement('dnsType', 420, 2, type=pyfixbuf.DataType.UINT8))
        import_template = pyfixbuf.Template(infomodel)
        import_template.add_spec_list(self._import_elements)
        export_template = pyfixbuf.Template(infomodel)
        export_template.add_spec_list(self._export_elements)
        if self.config['benchmark']:
            self._create_benchmark_records(infomodel, export_template)
        else:
            self._record = pyfixbuf.Record(infomodel, export_template)

        if not self.config['benchmark']:
            self._receiver = FixReceiver(infomodel, import_template, self.config)
            self._receiver.setup()
        for i in range(0, self.config['malfix_instances']):
            ipfix_sender = FixSender(infomodel, export_template, self.config['malfix_base_port'] + i, self.config)
            ipfix_sender.setup()
            ipfix_sender.export_templates()
            self._sender.append(ipfix_sender)

    def _balance(self, record: pyfixbuf.Record):
        self._sender[self._current_sender].send_ipfix(record)
        self._current_sender = (self._current_sender + 1) % len(self._sender)

        self._delta_packet_count += 1
        current_time = time.time()
        elapsed_time = current_time - self._last_report_time
        if elapsed_time >= 10.0:  # Report packets/sec every second
            packets_per_sec = self._delta_packet_count / elapsed_time
            self._packets_per_second.append(packets_per_sec)
            self._total_packet_count += self._delta_packet_count
            if not self.config['minimal_log']:
                print(f"flows/sec: {round(packets_per_sec)}, total: {self._total_packet_count}")
            self._delta_packet_count = 0
            self._last_report_time = current_time

    def run(self):
        self._receiver.listen(self._balance)

    def run_benchmark(self):
        while True:
            self._balance(random.choice(self._benchmark_records))
            if (self.config['max_flows'] != 0 and
                    self._total_packet_count + self._delta_packet_count >= self.config['max_flows']):
                [sender.emit() for sender in self._sender]

                if self.config['minimal_log']:
                    print(
                        f"Flows: {self.config['max_flows']}, "
                        f"Types: {self.config['malicious_types']}, "
                        f"Percentage: {self.config['malicious_percentage']}, "
                        f"Instances: {self.config['malfix_instances']}, "
                        f"Proto: {self.config['malfix_protocol']}"
                    )
                if len(self._packets_per_second) > 1:
                    # First one is always off
                    self._packets_per_second.pop()
                    print(f"f/s: {round(statistics.fmean(self._packets_per_second))}, "
                          f"Flows: {self._total_packet_count + self._delta_packet_count}\n")
                else:
                    print(f"Flows: {self._total_packet_count + self._delta_packet_count}\n")
                break

    def _create_benchmark_records(self, infomodel, export_template):
        malicious_count = int(self.config['malicious_percentage'] * 10_000)
        for i in range(0, 10_000):
            if i % 1_000 == 0:
                print(f"Generated {(i / 10_000) * 100}% of benchmark flows.")
            self._benchmark_records.append(pyfixbuf.Record(infomodel, export_template))
            record = self._benchmark_records[i]
            info = self._malicious_benchmark_data[
                i % len(self._malicious_benchmark_data)] if i < malicious_count else {}

            dns = False
            if info.get("dnsName") or info.get("type") != "ip" and choice([True, False], 1,
                                                                          p=[self.config["dns_percentage"],
                                                                             1 - self.config["dns_percentage"]]):
                record["dnsName"] = info.get("dnsName", random_dns[str(random.randint(0, len(random_dns) - 1))])
                record["dnsType"] = info.get("dnsType", random.choice([1, 28]))
                dns = True
            if info.get("type") == "ip" or choice([True, False], 1,
                                                  p=[0.6, 0.4]):
                record["sourceIPv4Address"] = info.get("sourceIPv4Address", get_random_ipv4())
                record["destinationIPv4Address"] = info.get("destinationIPv4Address", get_random_ipv4())

            else:
                record["sourceIPv6Address"] = info.get("sourceIPv6Address", get_random_ipv6())
                record["destinationIPv6Address"] = info.get("destinationIPv6Address", get_random_ipv6())

            record["sourceTransportPort"] = info.get("sourceTransportPort", random.randint(1, 65535))
            record["destinationTransportPort"] = 53 if dns else info.get(
                "destinationTransportPort", random.randint(1, 65535))
            record["protocolIdentifier"] = 17 if dns else 6 if info.get("type") == "ip" else random.choice([17, 6])
        print("Generated 100% of benchmark flows.")

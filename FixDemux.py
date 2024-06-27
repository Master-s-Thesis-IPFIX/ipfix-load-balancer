import random
import time
from typing import Optional

import pyfixbuf
import pyfixbuf.cert

import benchmark_data
from FixReceiver import FixReceiver
from FixSender import FixSender
from helper import Config


class FixDemux:
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

        self._malicious_benchmark_data = (
            [item for pair in zip(benchmark_data.malicious_dns, benchmark_data.malicious_ip) for item in pair]
            if "dns" in config['malicious_types'] and "ip" in config['malicious_types']
            else benchmark_data.malicious_dns
            if "dns" in config['malicious_types']
            else benchmark_data.malicious_ip)
        self._normal_benchmark_data = benchmark_data.normal

    def setup(self):
        infomodel = pyfixbuf.InfoModel()
        pyfixbuf.cert.add_elements_to_model(infomodel)
        infomodel.add_element(pyfixbuf.InfoElement('dnsName', 420, 2, type=pyfixbuf.DataType.STRING))
        infomodel.add_element(pyfixbuf.InfoElement('dnsType', 420, 3, type=pyfixbuf.DataType.UINT8))
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
            malfix = FixSender(infomodel, export_template, self.config['malfix_base_port'] + i, self.config)
            malfix.setup()
            malfix.export_templates()
            self._sender.append(malfix)

    def _demux(self, record: pyfixbuf.Record):
        self._sender[self._current_sender].send_ipfix(record)
        self._current_sender = (self._current_sender + 1) % len(self._sender)

        self._delta_packet_count += 1
        current_time = time.time()
        elapsed_time = current_time - self._last_report_time
        if elapsed_time >= 10.0:  # Report packets/sec every second
            packets_per_sec = self._delta_packet_count / elapsed_time
            self._total_packet_count += self._delta_packet_count
            print(f"records/sec: {round(packets_per_sec)}, total: {self._total_packet_count}")
            self._delta_packet_count = 0
            self._last_report_time = current_time

    def run(self):
        self._receiver.listen(self._demux)

    def run_benchmark(self):
        while True:
            self._demux(random.choice(self._benchmark_records))
            if (self.config['max_flows'] != 0 and
                    self._total_packet_count + self._delta_packet_count >= self.config['max_flows']):
                [sender.emit() for sender in self._sender]
                print(f"{self._total_packet_count + self._delta_packet_count} flows sent, exiting!")
                break

    def _create_benchmark_records(self, infomodel, export_template):
        malicious_count = int(self.config['malicious_percentage'] / 10)
        for i in range(0, 10):
            self._benchmark_records.append(pyfixbuf.Record(infomodel, export_template))
            record = self._benchmark_records[i]
            info = self._malicious_benchmark_data[
                i % len(self._malicious_benchmark_data)] if i < malicious_count else self._normal_benchmark_data[
                (i - malicious_count) % len(self._normal_benchmark_data)]
            if info["dnsName"]:
                record["dnsName"] = info["dnsName"]
                record["dnsType"] = info["dnsType"]
            if info["sourceIPv4Address"]:
                record["sourceIPv4Address"] = info["sourceIPv4Address"]
                record["destinationIPv4Address"] = info["destinationIPv4Address"]
            else:
                record["sourceIPv6Address"] = info["sourceIPv6Address"]
                record["destinationIPv6Address"] = info["destinationIPv6Address"]
            record["destinationTransportPort"] = info["destinationTransportPort"]
            record["sourceTransportPort"] = info["sourceTransportPort"]
            record["protocolIdentifier"] = info["protocolIdentifier"]

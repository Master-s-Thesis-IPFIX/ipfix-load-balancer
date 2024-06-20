import time
from typing import Optional

import pyfixbuf
import pyfixbuf.cert

from FixReceiver import FixReceiver
from FixSender import FixSender
from helper import Config


class FixDemux:
    def __init__(self, import_elements: list, export_elements: list, config: Config):
        self._import_elements: list = import_elements
        self._export_elements: list = export_elements

        self._receiver: Optional[FixReceiver] = None
        self._sender: list[FixSender] = []
        self._export_rec: Optional[pyfixbuf.Record] = None

        self._current_malfix: int = 0

        self._last_report_time = time.time()
        self._delta_packet_count = 0
        self._total_packet_count = 0
        self.config = config

    def setup(self):
        infomodel = pyfixbuf.InfoModel()
        pyfixbuf.cert.add_elements_to_model(infomodel)
        infomodel.add_element(pyfixbuf.InfoElement('dnsName', 420, 2, type=pyfixbuf.DataType.STRING))
        infomodel.add_element(pyfixbuf.InfoElement('dnsType', 420, 3, type=pyfixbuf.DataType.UINT8))
        import_template = pyfixbuf.Template(infomodel)
        import_template.add_spec_list(self._import_elements)
        export_template = pyfixbuf.Template(infomodel)
        export_template.add_spec_list(self._export_elements)
        self._export_rec = pyfixbuf.Record(infomodel, export_template)

        if not self.config['benchmark']:
            self._receiver = FixReceiver(infomodel, import_template, self.config)
            self._receiver.setup()
        for i in range(0, self.config['malfix_instances']):
            malfix = FixSender(infomodel, export_template, self.config['malfix_base_port'] + i, self.config)
            malfix.setup()
            malfix.export_templates()
            self._sender.append(malfix)

    def _demux(self, record: pyfixbuf.Record):
        self._sender[self._current_malfix].send_ipfix(record)
        self._current_malfix = (self._current_malfix + 1) % self.config['malfix_instances']

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
        self._export_rec["dnsName"] = "appdiscordgg.duckdns.org."
        self._export_rec["dnsType"] = 4
        self._export_rec["sourceIPv6Address"] = "fe80::a1a4:886b:1b26:c90f"
        self._export_rec["destinationIPv6Address"] = "fe80::69a5:40b0:2b5b:ba24"
        self._export_rec["destinationTransportPort"] = 53
        self._export_rec["sourceTransportPort"] = 3212
        self._export_rec["protocolIdentifier"] = 17

        while True:
            self._demux(self._export_rec)

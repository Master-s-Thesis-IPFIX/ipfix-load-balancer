import time
from typing import Optional

import pyfixbuf
import pyfixbuf.cert

from information_elements import export_ie


class MalFix:
    def __init__(self, infomodel: pyfixbuf.InfoModel, export_template: pyfixbuf.Template, port: str):
        self._export_session: Optional[pyfixbuf.Session] = None
        self._export_buffer: Optional[pyfixbuf.Buffer] = None
        self._listener: Optional[pyfixbuf.Listener] = None

        self._infomodel: pyfixbuf.InfoModel = infomodel
        self._export_template: pyfixbuf.Template = export_template
        self._port: str = port

    def setup_export(self):
        self._export_session = pyfixbuf.Session(self._infomodel)
        export_template_id = self._export_session.add_template(self._export_template)
        exporter = pyfixbuf.Exporter()
        exporter.init_net("127.0.0.1", "tcp", self._port)
        self._export_buffer = pyfixbuf.Buffer()
        self._export_buffer.init_export(self._export_session, exporter)
        self._export_buffer.set_internal_template(export_template_id)
        self._export_buffer.set_export_template(export_template_id)

    def export_templates(self):
        self._export_session.export_templates()

    def send_ipfix(self, record: pyfixbuf.Record):
        self._export_buffer.append(record)


class MalFixDeMux:
    def __init__(self):
        self._export_elements: Optional[list] = None
        self._malfixs: list[MalFix] = []
        self._export_rec: Optional[pyfixbuf.Record] = None

    def setup(self):
        self._export_elements = export_ie
        infomodel = pyfixbuf.InfoModel()
        pyfixbuf.cert.add_elements_to_model(infomodel)
        infomodel.add_element(pyfixbuf.InfoElement('maltrail', 420, 1, type=pyfixbuf.DataType.STRING))
        infomodel.add_element(pyfixbuf.InfoElement('dnsName', 420, 2, type=pyfixbuf.DataType.STRING))
        infomodel.add_element(pyfixbuf.InfoElement('dnsType', 420, 3, type=pyfixbuf.DataType.UINT8))

        export_template = pyfixbuf.Template(infomodel)
        export_template.add_spec_list(self._export_elements)

        self._export_rec = pyfixbuf.Record(infomodel, export_template)

        self._export_rec["dnsName"] = "appdiscordgg.duckdns.org."
        self._export_rec["dnsType"] = 4
        self._export_rec["sourceIPv6Address"] = "fe80::a1a4:886b:1b26:c90f"
        self._export_rec["destinationIPv6Address"] = "fe80::69a5:40b0:2b5b:ba24"
        self._export_rec["destinationTransportPort"] = 53
        self._export_rec["sourceTransportPort"] = 3212
        self._export_rec["protocolIdentifier"] = 17

        for i in range(0, 8):
            malfix = MalFix(infomodel, export_template, f"{18000+i}")
            malfix.setup_export()
            self._malfixs.append(malfix)

    def run(self):
        start_time = time.time()
        last_report_time = start_time
        delta_packet_count = 0
        total_packet_count = 0

        for malfix in self._malfixs:
            malfix.export_templates()
        while True:
            for malfix in self._malfixs:
                malfix.send_ipfix(self._export_rec)
                delta_packet_count += 1
                current_time = time.time()
                elapsed_time = current_time - last_report_time

                if elapsed_time >= 10.0:  # Report packets/sec every second
                    packets_per_sec = delta_packet_count / elapsed_time
                    total_packet_count += delta_packet_count
                    print(f"Packets/sec: {round(packets_per_sec)}, total: {total_packet_count}")
                    delta_packet_count = 0
                    last_report_time = current_time


multiFix = MalFixDeMux()
multiFix.setup()
multiFix.run()

from typing import Optional

import pyfixbuf

from helper import Config


class FixSender:
    def __init__(self, infomodel: pyfixbuf.InfoModel, template: pyfixbuf.Template, port: int, config: Config):
        self._session: Optional[pyfixbuf.Session] = None
        self._buffer: Optional[pyfixbuf.Buffer] = None
        self._record: Optional[pyfixbuf.Record] = None

        self._infomodel: pyfixbuf.InfoModel = infomodel
        self._template: pyfixbuf.Template = template

        self._port: int = port
        self.config = config

    def setup(self):
        self._session = pyfixbuf.Session(self._infomodel)
        export_template_id = self._session.add_template(self._template)
        exporter = pyfixbuf.Exporter()
        exporter.init_net(self.config['malfix_host'], self.config['malfix_protocol'], self._port)
        self._record = pyfixbuf.Record(self._infomodel, self._template)
        self._buffer = pyfixbuf.Buffer(self._record)
        self._buffer.init_export(self._session, exporter)
        self._buffer.set_internal_template(export_template_id)
        self._buffer.set_export_template(export_template_id)

    def export_templates(self):
        self._session.export_templates()

    def send_ipfix(self, record: pyfixbuf.Record):
        if self.config['benchmark']:
            self._record = record
        else:
            self._record.copy(record)
        try:
            self._buffer.append(self._record)
        except Exception as e:
            print(e)

    def emit(self):
        self._buffer.emit()

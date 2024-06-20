from numbers import Number
from typing import Optional

import pyfixbuf

import helper
from helper import Config


class FixReceiver:
    def __init__(self, infomodel: pyfixbuf.InfoModel, template: pyfixbuf.Template, config: Config):
        self._buffer: Optional[pyfixbuf.Buffer] = None
        self._listener: Optional[pyfixbuf.Listener] = None
        self._record: Optional[pyfixbuf.Record] = None
        self._infomodel: pyfixbuf.InfoModel = infomodel
        self._template: pyfixbuf.Template = template
        self._template_id: Optional[Number] = None

        self.config = config

    def setup(self):
        session = pyfixbuf.Session(self._infomodel)
        self._template_id = session.add_internal_template(self._template)
        self._record = pyfixbuf.Record(self._infomodel, self._template)
        self._listener = pyfixbuf.Listener(session, self.config['listen_host'], self.config['listen_protocol'],
                                           self.config["listen_port"])

    def listen(self, on_new_record):
        while True:
            try:
                data = next(self._buffer)
            except (StopIteration, TypeError):
                if not self._listener:
                    break
                else:
                    self._buffer = self._listener.wait()
                    self._buffer.set_record(self._record)
                    self._buffer.set_internal_template(self._template_id)
                    continue
            dns_info = helper.extract_yaf_dns_info(data)
            if dns_info[1] != 0:
                data["dnsName"] = dns_info[0]
                data["dnsType"] = dns_info[1]
            on_new_record(data)

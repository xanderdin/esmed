#
#   Copyright 2015 Alexander Pravdin <aledin@mail.ru>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#

from twisted.application import service
from twisted.internet import task, reactor

from txpostgres import txpostgres, reconnection

from ptsmpp.twisted.client import SMPPClientTransceiver, SMPPClientTransmitter
from ptsmpp.twisted.config import SMPPClientConfig
from ptsmpp.pdu.operations import SubmitSM, SubmitSMResp, DeliverSM
from ptsmpp.pdu.pdu_types import RegisteredDelivery, RegisteredDeliveryReceipt
from ptsmpp.pdu.pdu_types import EsmClassType, AddrTon, AddrNpi
from ptsmpp.pdu.pdu_types import PriorityFlag, DataCoding, DataCodingDefault

import logging


__author__ = 'Alexander Pravdin <aledin@mail.ru>'


CFG_DB_HOST = 'host'
CFG_DB_PORT = 'port'
CFG_DB_NAME = 'name'
CFG_DB_USER = 'user'
CFG_DB_PASS = 'pass'
CFG_DB_SSL_MODE = 'sslmode'


FLD_HOST = 'host'
FLD_PORT = 'port'
FLD_ESME_SYSTEM_ID = 'esme_system_id'
FLD_ESME_PASSWORD = 'esme_password'
FLD_ESME_SOURCE_ADDR = 'esme_source_addr'
FLD_ESME_BIND_TRANSCEIVER = 'esme_bind_transceiver'
FLD_ESME_REGISTERED_DELIVERY = 'esme_registered_delivery'
FLD_ESME_MAX_SUBMISSION_ATTEMPTS = 'esme_max_submission_attempts'
FLD_SMPP_SESSION_INIT_TIMER = 'smpp_session_init_timer'
FLD_SMPP_ENQUIRE_LINK_TIMER = 'smpp_enquire_link_timer'
FLD_SMPP_INACTIVITY_TIMER = 'smpp_inactivity_timer'
FLD_SMPP_RESPONSE_TIMER = 'smpp_response_timer'
FLD_SMPP_PDU_READ_TIMER = 'smpp_pdu_read_timer'


smpp_servers_query_fields_list = [
    FLD_HOST,
    FLD_PORT,
    FLD_ESME_SYSTEM_ID,
    FLD_ESME_PASSWORD,
    FLD_ESME_SOURCE_ADDR,
    FLD_ESME_BIND_TRANSCEIVER,
    FLD_ESME_REGISTERED_DELIVERY,
    FLD_ESME_MAX_SUBMISSION_ATTEMPTS,
    FLD_SMPP_SESSION_INIT_TIMER,
    FLD_SMPP_ENQUIRE_LINK_TIMER,
    FLD_SMPP_INACTIVITY_TIMER,
    FLD_SMPP_RESPONSE_TIMER,
    FLD_SMPP_PDU_READ_TIMER,
]


message_encoders_map = {
    'SMSC_DEFAULT_ALPHABET': None,
    'IA5_ASCII': 'ASCII',
    'OCTET_UNSPECIFIED': None,
    'LATIN_1': 'ISO-8859-1',
    'OCTET_UNSPECIFIED_COMMON': None,
    'JIS': None,
    'CYRILLIC': 'ISO-8859-5',
    'ISO_8859_8': 'ISO_8859-8',
    'UCS2': 'UTF-16BE',
    'PICTOGRAM': None,
    'ISO_2022_JP': 'ISO-2022-JP',
    'EXTENDED_KANJI_JIS': None,
    'KS_C_5601': None,
}


def get_db_config_dict(config, section):

    r = {
        CFG_DB_HOST: 'localhost',
        CFG_DB_PORT: '5432',
        CFG_DB_NAME: 'esmed',
        CFG_DB_USER: 'esmed',
        CFG_DB_PASS: 'pass',
        CFG_DB_SSL_MODE: 'disable',
    }

    for k in r.keys():
        if config.has_option(section, k):
            r[k] = config.get(section, k)

    return r


def new_smpp_conf(smsc_conf_dict):
    """
    Construct a new L{SMPPClientConfig} object

    :param smsc_conf_dict: SMSC configuration dictionary
    :return: a new L{SMPPClientConfig} object
    """
    smpp_conf = SMPPClientConfig(host=smsc_conf_dict[FLD_HOST],
                                 port=smsc_conf_dict[FLD_PORT],
                                 username=smsc_conf_dict[FLD_ESME_SYSTEM_ID],
                                 password=smsc_conf_dict[FLD_ESME_PASSWORD],
                                 addressTon=AddrTon.ALPHANUMERIC,
                                 addressNpi=AddrNpi.UNKNOWN,
                                 sessionInitTimerSecs=smsc_conf_dict[FLD_SMPP_SESSION_INIT_TIMER],
                                 enquireLinkTimerSecs=smsc_conf_dict[FLD_SMPP_ENQUIRE_LINK_TIMER],
                                 inactivityTimerSecs=smsc_conf_dict[FLD_SMPP_INACTIVITY_TIMER],
                                 responseTimerSecs=smsc_conf_dict[FLD_SMPP_RESPONSE_TIMER],
                                 pduReadTimerSecs=smsc_conf_dict[FLD_SMPP_PDU_READ_TIMER],
                                 )
    return smpp_conf


def new_esme(db, smsc_conf_dict):
    """
    Construct a new ESME object

    :param db: L{Db} object
    :param smsc_conf_dict: SMSC configuration dictionary
    :return: A new ESME object
    """
    esme = ESME(db,
                smsc_conf_dict[FLD_ESME_BIND_TRANSCEIVER],
                smsc_conf_dict[FLD_ESME_REGISTERED_DELIVERY],
                smsc_conf_dict[FLD_ESME_MAX_SUBMISSION_ATTEMPTS]
                )
    return esme


def make_smsc_conf_dict(db_result_row):
    """
    Construct an SMSC configuration dictionary from DB result row

    :param db_result_row: DB result row
    :return: SMSC configuration dictionary
    """
    res = dict()
    for v in smpp_servers_query_fields_list:
        res[v] = db_result_row[smpp_servers_query_fields_list.index(v)]
    return res


class Db:

    def __init__(self, config, section, detector):
        """
        Db
        :param config: L{ConfigParser} object
        :param section: Config file section name with settings for this Db
        :param detector: L{txpostgres.reconnection.DeadConnectionDetector} object
        """
        self.conf = get_db_config_dict(config, section)
        self.conn = txpostgres.Connection(detector=detector)

    def connect(self):
        d = self.conn.connect(host=self.conf[CFG_DB_HOST],
                              port=self.conf[CFG_DB_PORT],
                              user=self.conf[CFG_DB_USER],
                              password=self.conf[CFG_DB_PASS],
                              database=self.conf[CFG_DB_NAME],
                              sslmode=self.conf[CFG_DB_SSL_MODE])
        d.addErrback(self.conn.detector.checkForDeadConnection)
        return d


class DbDetector(reconnection.DeadConnectionDetector):
    """
    Object of this class performs needed actions on
    database reconnection events.
    """
    def __init__(self, caller_service):
        super(DbDetector, self).__init__()
        self.service = caller_service

    def startReconnecting(self, f):
        self.service.on_db_disconnected()
        return reconnection.DeadConnectionDetector.startReconnecting(self, f)

    def reconnect(self):
        self.service.on_db_reconnect()
        return reconnection.DeadConnectionDetector.reconnect(self)

    def connectionRecovered(self):
        self.service.on_db_connected(None)
        return reconnection.DeadConnectionDetector.connectionRecovered(self)


class EsmeService(service.Service):

    def __init__(self, config):
        self.setName(__name__)
        self.log = logging.getLogger(__name__)
        self.config = config
        self.smsc_conf_dict = None
        self.db = None
        self.db_checker_loop = None
        self.esme = None

    def startService(self):
        self.log.info('Started')
        self.db = Db(self.config, 'database', DbDetector(self))
        self.log.info('Connecting to DB...')
        d = self.db.connect()
        d.addCallbacks(self.on_db_connected, self.on_error)

    def stopService(self):
        self.log.info('Exiting...')
        d = service.Service.stopService(self)
        if d is None:
            self.on_service_stopped()
        else:
            d.addCallbacks(self.on_service_stopped, self.on_error)

    def on_service_stopped(self, _=None):
        self.log.info('Bye.')

    def on_error(self, e):
        if e is None:
            self.log.error('Error: UNKNOWN')
        else:
            self.log.error('Error: %r' % e.value)

    def on_db_connected(self, _):
        self.log.info('Connected to DB')
        self.db_checker_loop = task.LoopingCall(self.check_db_conn)
        self.db_checker_loop.start(5)

    def check_db_conn(self):
        self.log.info('Checking DB connection...')
        d = self.db.conn.runQuery('SELECT 1')
        d.addCallbacks(self.on_db_conn_ok, self.on_error)

    def on_db_conn_ok(self, _):
        self.log.info('DB connection is OK')
        self.db_checker_loop.stop()
        self.db_checker_loop = None
        self.load_esme()

    def on_db_reconnect(self):
        self.log.info('Reconnecting to DB...')

    def on_db_disconnected(self):
        self.log.info('Disconnected from DB')
        if self.db_checker_loop:
            self.db_checker_loop.stop()
            self.db_checker_loop = None
        self.stop_esme()

    def load_esme(self):
        d = self.run_smpp_servers_query()
        d.addCallbacks(self.run_esme, self.on_error)
        self.db.conn.addNotifyObserver(self.on_smpp_servers_table_change)
        d.addCallbacks(lambda _: self.db.conn.runOperation('LISTEN notify_table_change'), self.on_error)

    def on_smpp_servers_table_change(self, notify):
        """
        React on asynchronous notification from DB
        when smpp_servers table changes

        :param notify: Notification data
        """
        if notify.payload == 'smpp_servers':
            d = self.run_smpp_servers_query()
            d.addCallbacks(self.restart_esme, self.on_error)

    def run_smpp_servers_query(self):
        """
        Get configuration for SMPP server from DB

        :return: L{Deferred} for the query result
        """
        ql = list(['SELECT'])
        ql.append(', '.join(smpp_servers_query_fields_list))
        ql.append("FROM smpp_servers WHERE enabled IS TRUE AND TRIM(host) <> '' ORDER BY host, port LIMIT 1")
        q = ' '.join(ql)
        d = self.db.conn.runQuery(q)
        return d

    def run_esme(self, smsc_list):
        """
        Prepare and start an ESME instance

        :param smsc_list: A list of query results from smpp_servers table
        """
        if not smsc_list:
            return
        self.do_esme(make_smsc_conf_dict(smsc_list[0]))

    def do_esme(self, smsc_conf_dict):
        self.smsc_conf_dict = smsc_conf_dict
        if self.esme is None:
            self.esme = new_esme(self.db, smsc_conf_dict)
        self.esme.connect(smsc_conf_dict)

    def drop_esme(self):
        """
        Shut down ESME's connection to SMSC and initiate ESME object deletion
        """
        if self.esme is not None:
            self.esme.shutdown()
            self.esme = None
            self.smsc_conf_dict = None

    def restart_esme(self, smsc_list):
        """
        Restart an ESME

        :param smsc_list: A list of query results from smpp_servers table
        """
        if not smsc_list:
            # No servers in DB, stop ESME and don't restart it
            self.drop_esme()
            return
        smsc_conf_dict = make_smsc_conf_dict(smsc_list[0])
        if smsc_conf_dict == self.smsc_conf_dict:
            # Configuration did't change, do not restart
            return
        self.drop_esme()
        self.do_esme(smsc_conf_dict)

    def stop_esme(self):
        pass


class ESME:

    def __init__(self, db, bind_transceiver=False, registered_delivery=False, max_submission_attempts=3):
        self.log = logging.getLogger(__name__)
        self.db = db
        self.smpp_conf_dict = None
        self.bind_transceiver = bind_transceiver
        self.registered_delivery = registered_delivery
        self.max_submission_attempts = max_submission_attempts
        self.smpp_conn = None
        self.reconnect = False
        self.reconnect_task = None

    def connect(self, smpp_conf_dict):
        """
        Connect to SMPP server

        :param smpp_conf_dict: SMPP configuration dictionary
        :return: -L{Deferred} for SMPP server connection
        """
        self.smpp_conf_dict = smpp_conf_dict
        smpp_conf = new_smpp_conf(smpp_conf_dict)
        self.reconnect = True
        if self.bind_transceiver:
            d = SMPPClientTransceiver(smpp_conf, self.handle_msg).connectAndBind()
        else:
            d = SMPPClientTransmitter(smpp_conf).connectAndBind()
        d.addCallbacks(self.on_connected, self.on_connect_error)
        return d

    def handle_msg(self, smpp_conn, pdu):
        """
        Handle received PDU

        :param smpp_conn:
        :param pdu:
        """
        if 'data_coding' in pdu.params:
            smpp_data_coding = str(pdu.params['data_coding'].schemeData)
        else:
            smpp_data_coding = str(DataCodingDefault.SMSC_DEFAULT_ALPHABET)

        is_delivery_receipt = False

        if isinstance(pdu, DeliverSM):
            if 'esm_class' in pdu.params:
                if pdu.params['esm_class'].type == EsmClassType.SMSC_DELIVERY_RECEIPT:
                    is_delivery_receipt = True

        fl = list(['pdu_raw', 'pdu_parsed'])            # fields list
        vl = list([pdu.raw_hex, str(pdu)])              # values list
        ld = {'source_addr': '?', 'short_message': ''}  # dictionary for logging

        for p in ld.keys():
            if p in pdu.params:
                fl.append('smpp_' + p)
                if p == 'short_message':
                    ld[p] = self.decode_short_message(pdu.params[p], smpp_data_coding, is_delivery_receipt)
                else:
                    ld[p] = pdu.params[p]
                vl.append(ld[p])

        self.log.info('%s > %r' % (ld['source_addr'], ld['short_message'],))

        # constructing query
        ql = list(['INSERT INTO smpp_rx_queue ('])
        ql.append(','.join(fl))
        ql.append(') VALUES (')
        ql.append(','.join([r'%s' for v in vl]))
        ql.append(')')

        q = ''.join(ql)

        d = self.db.conn.runOperation(q, vl)

        if is_delivery_receipt:
            d.addCallback(self.save_delivery_state, pdu)

        d.addErrback(self.on_error)

    def save_delivery_state(self, _, pdu):
        """
        Save delivery state of sent SMS.

        :param _: placeholder, unused
        :param pdu: L{DeliverSM} pdu
        """
        if 'receipted_message_id' in pdu.params and 'message_state' in pdu.params:
            q = """
                UPDATE smpp_tx_queue SET
                    message_state_timestamp = now(),
                    smpp_message_state = %s
                WHERE smpp_message_id = %s AND smpp_message_state IS NULL
            """
            d = self.db.conn.runOperation(q, (
                str(pdu.params['message_state']),
                pdu.params['receipted_message_id'],))
            d.addErrback(self.on_error)

    def on_connected(self, smpp_conn):
        """
        Things to do when connected to SMPP server

        :param smpp_conn:
        """
        self.smpp_conn = smpp_conn
        d = self.smpp_conn.getDisconnectedDeferred()
        d.addCallbacks(self.on_disconnected, self.on_error)
        self.db.conn.addNotifyObserver(self.on_smpp_tx_queue_table_change)
        self.proc_sms()

    def do_reconnect(self):
        """
        Schedule SMPP server reconnection attempt
        """
        if self.reconnect:
            if self.reconnect_task is None or not self.reconnect_task.active():
                self.reconnect_task = reactor.callLater(5, self.connect, self.smpp_conf_dict)

    def on_connect_error(self, e):
        """
        Things to do on SMPP server connection error

        :param e: Error
        """
        self.do_reconnect()

    def on_disconnected(self, smpp_conn):
        """
        What to do on SMPP server disconnection

        :param smpp_conn:
        """
        self.do_reconnect()

    def shutdown(self):
        """
        Close SMPP server connection and do some clean-up
        """
        self.reconnect = False
        if self.db is not None and self.db.conn is not None:
            self.db.conn.removeNotifyObserver(self.on_smpp_tx_queue_table_change)
        if self.reconnect_task is not None:
            if self.reconnect_task.active():
                self.reconnect_task.cancel()
            self.reconnect_task = None
        if self.smpp_conn is not None:
            self.smpp_conn.shutdown()
            self.smpp_conn = None
        if self.smpp_conf_dict is not None:
            self.smpp_conf_dict = None

    def on_smpp_tx_queue_table_change(self, notify):
        """
        Things to do on asynchronous notification from DB when
        smpp_tx_queue table changes

        :param notify: Notification data
        """
        if not notify.payload:
            return
        if notify.payload == 'smpp_tx_queue':
            self.proc_sms()

    def proc_sms(self):
        """
        Get unsent SMSes from DB and put them to sending method

        :return: L{Deferred} query result with list of unsent SMSes
        """
        q = """
            SELECT
                id,
                insert_timestamp,
                smpp_destination_addr,
                smpp_short_message,
                submission_attempts,
                smpp_priority_flag,
                smpp_registered_delivery
            FROM smpp_tx_queue
                WHERE submission_done IS FALSE AND submission_failed IS FALSE
                    ORDER BY id
        """
        d = self.db.conn.runQuery(q)
        d.addCallbacks(self.send_sms, self.on_error)
        return d

    def send_sms(self, sms_list):
        """
        Send SMSes from resulting DB list of unsent SMSes

        :param sms_list: List of unsent SMSes
        """
        if not sms_list:
            # Nothing to send
            return

        # If send operation fails the next line
        # gives a chance to try it again
        reactor.callLater(5, self.proc_sms)

        for sms in sms_list:
            sms_id, insert_timestamp, smpp_destination_addr, smpp_short_message,\
            submission_attempts, smpp_priority_flag, smpp_registered_delivery = sms

            smpp_data_coding = 'SMSC_DEFAULT_ALPHABET'

            # If non-7-bit printable characters present, then use UCS2 encoding.
            if [c for c in smpp_short_message if ord(c) not in range(32,128)]:
                smpp_data_coding = 'UCS2'

            self.log.info('%s < %r' % (smpp_destination_addr, smpp_short_message,))

            esme_source_addr = self.smpp_conf_dict[FLD_ESME_SOURCE_ADDR]
            priority_flag = getattr(PriorityFlag, smpp_priority_flag)
            data_coding = DataCoding(schemeData=getattr(DataCodingDefault, smpp_data_coding))
            smpp_short_message = self.encode_short_message(smpp_short_message, smpp_data_coding)

            registered_delivery = RegisteredDelivery(RegisteredDeliveryReceipt.NO_SMSC_DELIVERY_RECEIPT_REQUESTED)

            if self.bind_transceiver:
                if self.registered_delivery:  # if a global flag is set
                    registered_delivery = RegisteredDelivery(RegisteredDeliveryReceipt.SMSC_DELIVERY_RECEIPT_REQUESTED)
                else:  # if per-message flag is set
                    registered_delivery = RegisteredDelivery(getattr(RegisteredDeliveryReceipt,
                                                                     smpp_registered_delivery))
            pdu = SubmitSM(destination_addr=smpp_destination_addr,
                           source_addr=esme_source_addr,
                           source_addr_ton=AddrTon.ALPHANUMERIC,
                           source_addr_npi=AddrNpi.UNKNOWN,
                           dest_addr_ton=AddrTon.INTERNATIONAL,
                           dest_addr_npi=AddrNpi.ISDN,
                           short_message=smpp_short_message,
                           priority_flag=priority_flag,
                           data_coding=data_coding,
                           registered_delivery=registered_delivery)

            d = self.smpp_conn.sendDataRequest(pdu)

            d.addCallbacks(callback=self.mark_sms_as_sent,
                           errback=self.on_send_sms_error,
                           callbackArgs=(sms,),
                           errbackArgs=(sms,))

    def mark_sms_as_sent(self, data, sms):
        """
        Mark sent SMS as sent in DB table

        :param data: Contains smpp_conn, request and response objects
        :param sms: Sent SMS data
        """
        sms_id = sms[0]
        submission_attemps = sms[4]
        submission_attemps += 1
        smpp_conn, request, response = data
        message_id = None
        if isinstance(response, SubmitSMResp):
            message_id = response.params['message_id']
        ql = list(['UPDATE smpp_tx_queue SET submission_timestamp = now()'])
        ql.append(', submission_done = TRUE, submission_failed = FALSE, submission_attempts = %s')
        if message_id:
            ql.append(', smpp_message_id = %s')
        ql.append(' WHERE id = %s')
        q = ''.join(ql)
        if message_id:
            d = self.db.conn.runOperation(q, (submission_attemps, message_id, sms_id,))
        else:
            d = self.db.conn.runOperation(q, (submission_attemps, sms_id,))
        d.addErrback(self.on_error)

    def on_send_sms_error(self, e, sms):
        """
        Mark sent SMS as failed in DB table

        :param e: Error which occurred
        :param sms: Sent SMS
        """
        self.on_error(e)
        sms_id = sms[0]
        submission_attempts = sms[4]
        submission_attempts += 1
        ql = list(['UPDATE smpp_tx_queue SET submission_timestamp = now()'])
        ql.append(', submission_done = FALSE, submission_attempts = %s')
        failed = False
        if submission_attempts >= self.max_submission_attempts:
            failed = True
        if failed:
            ql.append(', submission_failed = TRUE, submission_info = %s')
        ql.append(' WHERE id = %s')
        q = ''.join(ql)
        if failed:
            d = self.db.conn.runOperation(q, (submission_attempts, str(e.value), sms_id,))
        else:
            d = self.db.conn.runOperation(q, (submission_attempts, sms_id,))
        d.addBoth(self.on_error)

    def on_error(self, e):
        if e is None:
            self.log.error('Error: UNKNOWN')
        else:
            self.log.error('Error: %r' % e.value)

    def encode_short_message(self, msg, data_coding):
        """
        Encode short message before sending.

        :param msg: The message in UTF-8.
        :param data_coding: Data coding name
        :return: Encoded message (if encoding was successful).
        """
        return self._code_short_message(msg, data_coding, True)

    def decode_short_message(self, msg, data_coding, is_delivery_receipt=False):
        """
        Decode received short message before storing it to DB.

        :param msg: Received short message
        :param data_coding: Data coding name
        :param is_delivery_receipt: Received short message is a delivery receipt
        :return: Decoded message (if decoding was successful)
        """
        return self._code_short_message(msg, data_coding, False, is_delivery_receipt)

    def _code_short_message(self, msg, data_coding, encode, is_delivery_receipt=False):
        """
        Encode/decode short message.

        :param msg: The message.
        :param data_coding: Data coding name
        :param encode: If True, then encode; if False, then decode
        :param is_delivery_receipt: Received short message is a delivery receipt
        :return: Coded message (if coding was successful).
        """
        res = msg

        try:
            if data_coding in message_encoders_map and message_encoders_map[data_coding]:
                if encode:
                    res = msg.decode('UTF-8').encode(message_encoders_map[data_coding])
                else:  # decode
                    if is_delivery_receipt:
                        # There're errors in decoding delivery receipt messages the usual way.
                        # So, need to split such messages in two parts - the status part and
                        # the text part. After splitting decode only the text part.
                        import re
                        match = re.match('(^id:.*ext:)(.*)$', msg)
                        if match:
                            (a, b) = match.groups()
                            res = unicode(a) + b.decode(message_encoders_map[data_coding])
                        else:
                            pass
                    else:  # decode message the usual way
                        res = msg.decode(message_encoders_map[data_coding])
        except Exception as e:
            self.log.error("Error %r" % str(e))

        return res

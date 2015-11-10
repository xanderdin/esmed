SMPP ESME daemon (esmed)
========================

SMPP ESME daemon (esmed) is an SMPP client application for sending short
messages (SMS) through an SMPP server (SMSC). It can connect to an SMPP
server as a transmitter or as a transceiver. ESME daemon uses PostgreSQL
as its backend database. It's also build on Twisted framework, so to run
it you need twistd daemon.


Requirements
------------
* Twisted
* PostgreSQL
* psycopg2
* txpostgres
* ptsmpp


Installation on Debian
----------------------

If you're using Debian Linux system you can install esmed deb package
and then esmed will be started using the provided init.d script. Setup a
database (see below) using db.sql file and adjust configuration in the
/etc/esmed/esmed.conf file. Restart esmed in order to activate your
configuration. You can find db.sql file in /usr/share/doc/esmed/sql
directory after deb package installation.

Debian package can be found at https://github.com/xanderdin/esmed-dist-debian


Installation with PyPi
----------------------

If you're using PyPi then do the following. Unpack esmed-VERSION.tar.gz to
a temporary directory. Setup a database (see below) using sql/db.sql file.
Install esmed requirements:

  pip install -r requirements.txt

Install esmed package:

  pip install esmed-VERSION.tar.gz

You need to place configuration file cfg/esmed.conf manually to a preferred
location. Adjust it as needed and after that you can start esmed:

  twistd esmed -c path_to_your/esmed.conf


Database setup
--------------
Create a database (ex.: esmed), connect to it and execute commands from db.sql
file. This will add new database user 'esmed' and create a database structure.
Don't forget to change 'esmed' user password to you own secret and set that
secret as the database password in esmed.conf configuration file.


Adding SMPP server
------------------
Add to *smpp_servers* database table your SMPP server credentials. You can add
multiple servers to the *smpp_servers* table but only one of them can be
enabled as a working one. The daemon automatically notices changes to this
table and acts accordingly. Example:

  insert into smpp_servers (enabled, host, port, esme_system_id,
  esme_password) values (TRUE, 'server-address', 2775, 'my-login',
  'my-password');

Fields of the *smp_servers* table:

:enabled:
  If set to TRUE, the SMPP server credentials from this record
  will be used for connection.

:name:
  Name or description of the SMPP server. Used only for information.

:host:
  Network name or address of the SMPP server.

:port:
  SMPP server's port (default 2775).

:esme_system_id:
  Used as 'login' when connecting to the SMPP server.

:esme_password:
  Used as password when connecting to the SMPP server.

:esme_source_addr:
  An identification text that may be shown to the recipient of the message.

:esme_bind_transceiver:
  If set to TRUE then esmed will connect as a transceiver, otherwise
  it will connect as a transmitter.

:esme_registered_delivery:
  If set to TRUE, request a delivery receipt on transmitted messages.
  It does nothing if *esme_bind_transceiver* is set to FALSE.

:esme_max_submission_attempts:
  How many times to try to resubmit a message on error before giving up.

:smpp_*_timer:
  Those fields are timers measured in seconds. See SMPP v3.4 specification,
  ref. 7.2 for details.


Sending messages
----------------
In order to send a message add it to *smpp_tx_queue* database table. Example:

  insert into smpp_tx_queue (smpp_destination_addr, smpp_short_message)
  values ('some-phone-number', 'Hello, there!');

Fields of the *smpp_tx_queue* table:

:insert_timestamp:
  Timestamp of when the message was added. This is set automatically,
  you don't need to set it.

:smpp_destination_addr:
  Recipients address (usually a phone number). You must set it.

:smpp_priority_flag:
  Message priority. For GSM networks there're only two priorities:
    * non-priority (LEVEL_0) - default
    * priority (LEVEL_1)
  You may set it or not.

:smpp_registered_delivery:
  Request a delivery receipt for the message. It can be one of the following:
    * NO_SMSC_DELIVERY_RECEIPT_REQUESTED (default)
    * SMSC_DELIVERY_RECEIPT_REQUESTED
    * SMSC_DELIVERY_RECEIPT_REQUESTED_FOR_FAILURE
  Note that this field is only used when *esme_registered_delivery* field from
  the *smpp_servers* table is set to FALSE and the *esme_bind_transceiver* is
  set to TRUE. You are not required to set this field.

:smpp_short_message:
  Text of the short message. Note that if the message text is only 7-bit it
  will be sent using default SMSC coding scheme, but if it is 8-bit or Unicode
  (UTF-8) it will be sent using UCS2 coding scheme. You must put a message in
  this field.

:smpp_message_id:
  This field will be set by the esmed daemon after the message has been
  transmitted to SMSC server. The id is assigned by the SMSC server. Do not
  set this field yourself.

:smpp_message_state:
  If the delivery receipt is received this would be filled with one of the
  following:
    * ENROUTE
    * DELIVERED
    * EXPIRED
    * DELETED
    * UNDELIVERABLE
    * ACCEPTED
    * UNKNOWN
    * REJECTED
  This field is set by the esmed. Do not set this field yourself.

:message_state_timestamp:
  Timestamp of *smpp_message_state*. This field is set by the esmed. Do not
  set this field yourself.

:submission_timestamp:
  Timestamp of when we made the last submission attempt. This field is set
  by the esmed. Do not set this field yourself.

:submission_attempts:
  How many submission attempts we performed so far. This field is set by the
  esmed. Do not set this field yourself.

:submission_done:
  Set by esmed to TRUE on successful message transmission to the SMSC server.
  Do not set this filed yourself.

:submission_failed:
  Set by esmed to TRUE when it failed to transmit the message to SMSC server
  after number of *smpp_max_transmission_attempts*. Do not set this field
  yourself.

:submission_info:
  This could be filled by esmed with some error information on transmission
  failure. Do not set this field yourself.


Receiving messages
------------------
Delivery receipts and other incoming messages are saved to *smpp_rx_queue**
table.

Fields of the *smpp_rx_queue* table:

:insert_timestamp:
  Timestamp of when the message was received.

:pdu_raw:
  Unparsed raw hex string of received PDU. You can parse it using your
  preferred SMPP PDU parser if you want.

:pdu_parsed:
  Parsed version of received PDU. Parsed by the ptsmpp library.

:smpp_source_addr:
  Address of the sender.

:smpp_short_message:
  Received message text.

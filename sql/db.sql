--
--   Copyright 2015 Alexander Pravdin <aledin@mail.ru>
--
--   Licensed under the Apache License, Version 2.0 (the "License");
--   you may not use this file except in compliance with the License.
--   You may obtain a copy of the License at
--
--       http://www.apache.org/licenses/LICENSE-2.0
--
--   Unless required by applicable law or agreed to in writing, software
--   distributed under the License is distributed on an "AS IS" BASIS,
--   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
--   See the License for the specific language governing permissions and
--   limitations under the License.
--

-- Creating user role for the daemon.
-- Don't forget to change the password to your own secret
-- after creating this user role!!!
CREATE ROLE esmed LOGIN
    ENCRYPTED PASSWORD 'md5dc03442517e77aed9f84185ef9fed65f'
    NOSUPERUSER INHERIT NOCREATEDB NOCREATEROLE;


CREATE TYPE smpp_priority_flag AS ENUM (
    'LEVEL_0',
    'LEVEL_1',
    'LEVEL_2',
    'LEVEL_3'
);

CREATE TYPE smpp_registered_delivery AS ENUM (
    'NO_SMSC_DELIVERY_RECEIPT_REQUESTED',
    'SMSC_DELIVERY_RECEIPT_REQUESTED',
    'SMSC_DELIVERY_RECEIPT_REQUESTED_FOR_FAILURE'
);


-- Trigger function to keep only one SMPP server enabled.
CREATE OR REPLACE FUNCTION smpp_servers_only_one_enabled() RETURNS trigger AS $BODY$

begin
	if TG_OP = 'DELETE' then
		return OLD;
	end if;

	if NEW.enabled = TRUE then
		UPDATE smpp_servers SET enabled = FALSE WHERE id != NEW.id;
	end if;

	return NEW;
end;

$BODY$ LANGUAGE plpgsql;

-- Trigger function for dispatching notification events
-- To use it just create a trigger for the needed table
-- and set trigger's EXECUTE PROCEDURE to this function.
-- Notifications will contain that table name.
CREATE OR REPLACE FUNCTION notify_table_change() RETURNS trigger AS $BODY$

begin
	perform pg_notify('notify_table_change', TG_TABLE_NAME);

	if TG_OP = 'DELETE' then
		return OLD;
	end if;

	return NEW;
end;

$BODY$ LANGUAGE plpgsql STABLE;


-- SMPP servers table
CREATE TABLE smpp_servers
(
    id SERIAL PRIMARY KEY,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    name CHARACTER VARYING,
    host CHARACTER VARYING NOT NULL,
    port INTEGER NOT NULL DEFAULT 2775,
    esme_system_id CHARACTER VARYING(16) NOT NULL,         -- login
    esme_password CHARACTER VARYING(9) NOT NULL,           -- password
    esme_source_addr CHARACTER VARYING(21),                -- this will be shown to user as an SMS originator
    esme_bind_transceiver BOOLEAN NOT NULL DEFAULT FALSE,  -- connect to server as transceiver (TRUE) or transmitter (FALSE)
    esme_registered_delivery BOOLEAN NOT NULL DEFAULT FALSE,  -- require delivery receipt
    esme_max_submission_attempts INTEGER NOT NULL DEFAULT 3,  -- how many times to try to submit an SMS when errors occur
    smpp_session_init_timer INTEGER NOT NULL DEFAULT 30,   -- sec., see SMPP v3.4 spec, ref 7.2
    smpp_enquire_link_timer INTEGER NOT NULL DEFAULT 10,   -- sec., see SMPP v3.4 spec, ref 7.2
    smpp_inactivity_timer INTEGER NOT NULL DEFAULT 120,    -- sec., see SMPP v3.4 spec, ref 7.2
    smpp_response_timer INTEGER NOT NULL DEFAULT 60,       -- sec., see SMPP v3.4 spec, ref 7.2
    smpp_pdu_read_timer INTEGER NOT NULL DEFAULT 10,
    CONSTRAINT smpp_servers_idx01 UNIQUE (host, port)
);

-- SMPP queue for transmission
CREATE TABLE smpp_tx_queue
(
    id SERIAL PRIMARY KEY,
    insert_timestamp TIMESTAMP WITH TIME ZONE
        NOT NULL DEFAULT now(),
    smpp_destination_addr CHARACTER VARYING(21) NOT NULL,  -- usually a mobile phone number of a recipient
    smpp_priority_flag smpp_priority_flag NOT NULL         -- message priority
        DEFAULT 'LEVEL_0',
    smpp_registered_delivery smpp_registered_delivery NOT NULL  -- require delivery receipt
        DEFAULT 'NO_SMSC_DELIVERY_RECEIPT_REQUESTED',
    smpp_short_message CHARACTER VARYING(254) NOT NULL,    -- short message text
    smpp_message_id CHARACTER VARYING NULL,                -- message_id is assigned by the SMPP server
    smpp_message_state CHARACTER VARYING,                  -- sent message state from delivery receipt
    message_state_timestamp TIMESTAMP WITH TIME ZONE NULL, -- timestamp of when we got the delivery receipt
    submission_timestamp TIMESTAMP WITH TIME ZONE NULL,    -- timestamp of when we made the last submission attempt
    submission_attempts INTEGER NOT NULL DEFAULT 0,        -- number of submission attempts so far
    submission_done BOOLEAN NOT NULL DEFAULT FALSE,        -- if submission was successful this would be set to TRUE
    submission_failed BOOLEAN NOT NULL DEFAULT FALSE,      -- if submission_attempts >= esme_max_submission_attempts this would be set to TRUE
    submission_info CHARACTER VARYING                      -- this could be the last error message when submission_failed is set to TRUE
);

-- SMPP received queue
CREATE TABLE smpp_rx_queue
(
    id SERIAL PRIMARY KEY,
    insert_timestamp TIMESTAMP WITH TIME ZONE
        NOT NULL DEFAULT now(),
    pdu_raw CHARACTER VARYING,                             -- raw hex representation of received PDU
    pdu_parsed CHARACTER VARYING,                          -- parsed version of received PDU
    smpp_source_addr CHARACTER VARYING,                    -- message originator address
    smpp_short_message CHARACTER VARYING                   -- short message text
);


CREATE TRIGGER smpp_servers_only_one_enabled
  AFTER INSERT OR UPDATE
  ON smpp_servers
  FOR EACH ROW
  EXECUTE PROCEDURE smpp_servers_only_one_enabled();

CREATE TRIGGER smpp_servers_notify_change
    AFTER INSERT OR UPDATE OR DELETE
    ON smpp_servers
    FOR EACH ROW
    EXECUTE PROCEDURE notify_table_change();

CREATE TRIGGER smpp_tx_queue_notify_change
    AFTER INSERT
    ON smpp_tx_queue
    FOR EACH ROW
    EXECUTE PROCEDURE notify_table_change();


GRANT SELECT ON TABLE smpp_servers TO esmed;

GRANT SELECT, UPDATE ON TABLE smpp_tx_queue TO esmed;

GRANT INSERT ON TABLE smpp_rx_queue TO esmed;

GRANT SELECT, UPDATE ON SEQUENCE smpp_rx_queue_id_seq TO esmed;

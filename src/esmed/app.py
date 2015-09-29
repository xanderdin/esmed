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

import ConfigParser
import logging
import logging.config

from twisted.application import service
from twisted.python import usage, log

from . import esme

__author__ = 'Alexander Pravdin <aledin@mail.ru>'


def get_config(config_file):
    """
    Reads configuration file.

    :param config_file: Configuration file name.
    :return: L{ConfigParser} object with configuration from config_file
    """

    config = ConfigParser.ConfigParser()
    config.read(config_file)

    return config


def makeService(opts):
    try:
        opts.parseOptions()
    except usage.UsageError:
        pass

    config_file = opts['config']
    config = get_config(config_file)
    logging.config.fileConfig(config_file)
    observer = log.PythonLoggingObserver()
    observer.start()

    return esme.EsmeService(config)


application = service.Application('An SMPP ESME daemon')

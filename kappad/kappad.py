
"""
    1. Fill out the config skeleton and save as conf.ini in this directory
    2. $ python kappad.py
"""

from twisted.words.protocols import irc
from twisted.internet import reactor, protocol
from twisted.python import log

import sys, os
import datetime
import logging
import textwrap
import hmac
import hashlib

from logging import Formatter
from logging.handlers import RotatingFileHandler
from ConfigParser import SafeConfigParser

app_logger = None

class LogBot(irc.IRCClient):
    """A logging IRC bot."""
    
    def __init__(self, channel, nickname, username, password, message_logger, key):
        self.channel = channel
        self.nickname = nickname
        self.username = username
        self.password = password
        self.message_logger = message_logger
        self.key = key
        app_logger.debug(textwrap.dedent("""
                Initialized bot with channel: {channel},
                nick: {nickname},
                username: {username},
                password {password} """.format(channel = self.channel,
                    nickname = self.nickname,
                    username = self.username,
                    password = "****" + self.password[-4:] #Hope it's more than 4 chars
                    ))
                )

    def connectionMade(self):
        irc.IRCClient.connectionMade(self)
        app_logger.info("Connected to server")

    def connectionLost(self, reason):
        irc.IRCClient.connectionLost(self, reason)
        app_logger.info("Bot disconnected, caused by {reason}".format(reason = repr(reason)))

    def signedOn(self):
        app_logger.info("Signed on")
        self.join(self.channel)

    def joined(self, channel):
        app_logger.info("Joined channel {0}".format(channel))

    def privmsg(self, user, channel, msg):
        user = user.split('!', 1)[0]
        message = msg[:140]
        hmac_obj = hmac.new(self.key, user, hashlib.sha256)
        user_hash = hmac_obj.hexdigest()
        entry = "[{user}] {message}".format(user=user_hash, message=message).decode("utf-8")
        self.message_logger.info(entry)

    def irc_PING(self, prefix, params):
        app_logger.info("Received ping")

class LogBotFactory(protocol.ClientFactory):
    """A factory for LogBots.

    A new protocol instance will be created each time we connect to the server.

    Editor's note: I had a problem now I have a problem factory
    """

    def __init__(self, channel, nickname, username, password, message_log, key):
        self.nickname = nickname
        self.username = username
        self.password = password
        self.channel = channel
        self.message_log = message_log
        self.key = key

    def buildProtocol(self, addr):
        try:
            p = LogBot(self.channel,
                self.nickname,
                self.username,
                self.password,
                self.message_log,
                self.key
                )
            p.factory = self
        except Exception as e:
            app_logger.error("Failed to initialize bot because {0}".format(repr(e)))
            return None
        return p

    def clientConnectionLost(self, connector, reason):
        """If we get disconnected, attempt to reconnect."""
        app_logger.warn("Lost connection because {0}, attempt to reconnect".format(reason))
        connector.connect()

    def clientConnectionFailed(self, connector, reason):
        print "connection failed:", reason
        app_logger.warn("Connection failed because {0}, go home".format(reason))
        reactor.stop()

if __name__ == '__main__':

    config_parser = SafeConfigParser()
    config_parser.read('conf.ini')

    # Twisted output
    log.startLogging(sys.stdout)
    
    # Logger for basic application health info
    app_logger = logging.getLogger('app')
    app_handler = RotatingFileHandler(os.path.join(config_parser.get('app', 'log_dir'), 'app.log'),
            encoding = "utf-8",
            maxBytes = config_parser.getint('app', 'log_file_size'),
            backupCount=100
            )
    app_logger_format = Formatter('%(asctime)s - %(levelname)s - %(message)s')
    app_handler.setFormatter(app_logger_format)
    app_logger.addHandler(app_handler)
    app_logger.setLevel(logging.DEBUG)

    # Logger for messages received in channel
    message_handler = RotatingFileHandler(os.path.join(config_parser.get('app', 'log_dir'), 'messages.log'),
            encoding = "utf-8",
            maxBytes = config_parser.getint('app', 'messages_file_size'),
            backupCount=100
            )
    message_format = Formatter('%(asctime)s - %(message)s')
    message_handler.setFormatter(message_format)
    message_logger = logging.getLogger('messages')
    message_logger.addHandler(message_handler)
    message_logger.setLevel(logging.DEBUG)

    f = LogBotFactory(config_parser.get('irc', 'channel'),
            config_parser.get('irc', 'nick'),
            config_parser.get('irc', 'username'),
            config_parser.get('irc', 'password'),
            message_logger,
            config_parser.get('app', 'key'),
            )

    reactor.connectTCP(config_parser.get('irc', 'server'),
            config_parser.getint('irc', 'port'),
            f
            )
    reactor.run()

    handlers = message_logger.handlers[:]
    for handler in handlers:
        handler.close()
        message_logger.removeHandler(handler)
    handlers = app_logger.handlers[:]
    for handler in handlers:
        handler.close()
        app_logger.removeHandler(handler)


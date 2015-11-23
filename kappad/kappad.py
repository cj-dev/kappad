
"""
    1. Fill out the config skeleton and save as conf.ini in this directory
    2. $ python kappad.py
"""

from twisted.words.protocols import irc
from twisted.internet import reactor, protocol
from twisted.python import log

import time, sys
import datetime
import logging
import textwrap
from logging import Formatter
from logging.handlers import RotatingFileHandler
from ConfigParser import SafeConfigParser

app_logger = None

class LogBot(irc.IRCClient):
    """A logging IRC bot."""
    
    def __init__(self, channel, nickname, username, password, message_logger):
        self.channel = channel
        self.nickname = nickname
        self.username = username
        self.password = password
        self.message_logger = message_logger
        app_logger.debug(textwrap.dedent("""
                Initialized bot with {channel},
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
        self.message_logger.info("[{user}] {message}".format(user=user, message=msg[:140]))

    def irc_PING(self, prefix, params):
        app_logger.info("Received ping")

class LogBotFactory(protocol.ClientFactory):
    """A factory for LogBots.

    A new protocol instance will be created each time we connect to the server.

    Editor's note: I had a problem now I have a problem factory
    """

    def __init__(self, channel, nickname, username, password, message_log):
        self.nickname = nickname
        self.username = username
        self.password = password
        self.channel = channel
        self.message_log = message_log

    def buildProtocol(self, addr):
        try:
            p = LogBot(self.channel,
                self.nickname,
                self.username,
                self.password,
                self.message_log,
                )
            p.factory = self
        except:
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
    app_handler = RotatingFileHandler(config_parser.get('app', 'log_file'),
            maxBytes = config_parser.getint('app', 'log_file_size'),
            backupCount=100
            )
    app_logger_format = Formatter('%(asctime)s - %(levelname)s - %(message)s')
    app_handler.setFormatter(app_logger_format)
    app_logger.addHandler(app_handler)
    app_logger.setLevel(logging.DEBUG)

    # Logger for messages received in channel
    message_handler = RotatingFileHandler(config_parser.get('app', 'messages_file'),
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
            message_logger
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


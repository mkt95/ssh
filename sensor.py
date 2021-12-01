"""
Support for SSH access.

For more details about this platform, please refer to the documentation at
https://github.com/custom-components/sensor.ssh

"""
import base64
import paramiko
import logging
import voluptuous as vol
from datetime import timedelta
import json
import asyncio

from homeassistant.helpers.device_registry import format_mac
from homeassistant.helpers.entity import Entity
import homeassistant.helpers.config_validation as cv
from homeassistant.util import Throttle
from homeassistant.components.sensor import PLATFORM_SCHEMA
from homeassistant.const import (
    CONF_NAME, CONF_HOST, CONF_USERNAME, CONF_PASSWORD,
    CONF_VALUE_TEMPLATE, CONF_COMMAND, CONF_PORT,
    STATE_UNKNOWN, CONF_UNIT_OF_MEASUREMENT, CONF_UNIQUE_ID)

__version__ = '0.2.2'

_LOGGER = logging.getLogger(__name__)
DOMAIN = 'sensor'

DEFAULT_NAME = 'SSH'
DEFAULT_SSH_PORT = 22
DEFAULT_INTERVAL = 30
DEFAULT_UNIQUE_ID_SRC = 'cat /sys/class/net/eth0/address'

CONF_KEY = 'key'
CONF_KEYFILE = 'keyfile'
CONF_INTERVAL = 'interval'

MIN_TIME_BETWEEN_UPDATES = timedelta(seconds=30)

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Optional(CONF_NAME, default=DEFAULT_NAME): cv.string,
    vol.Required(CONF_HOST): cv.string,
    vol.Required(CONF_KEY): cv.string,
    vol.Optional(CONF_PASSWORD): cv.string,
    vol.Optional(CONF_KEYFILE): cv.string,
    vol.Required(CONF_USERNAME): cv.string,
    vol.Optional(CONF_PORT, default=DEFAULT_SSH_PORT): cv.port,
    vol.Required(CONF_COMMAND): cv.string,
    vol.Required(CONF_UNIT_OF_MEASUREMENT): cv.string,
    vol.Optional(CONF_VALUE_TEMPLATE): cv.template,
    vol.Optional(CONF_UNIQUE_ID, default=DEFAULT_UNIQUE_ID_SRC): cv.string,
})

@asyncio.coroutine
def async_setup_platform(hass, config, async_add_devices, discovery_info=None):

    dev = []
    dev.append(SSHSensor(hass, config))
    async_add_devices(dev, True)


class SSHSensor(Entity):

    def __init__(self, hass, config):
        """Initialize the scanner."""
        self._name = config.get(CONF_NAME)
        self._host = config.get(CONF_HOST)
        self._username = config.get(CONF_USERNAME)
        self._password = config.get(CONF_PASSWORD)
        self._keyfile = config.get(CONF_KEYFILE)
        self._key = config.get(CONF_KEY)
        self._interval = config.get(CONF_INTERVAL)
        self._port = config.get(CONF_PORT)
        self._command = config.get(CONF_COMMAND)
        self._value_template = config.get(CONF_VALUE_TEMPLATE)
        self._unit_of_measurement = config.get(CONF_UNIT_OF_MEASUREMENT)
        self._unique_id_command = config.get(CONF_UNIQUE_ID)
        self._state = None
        self._ssh = None
        self._connected = False
        self._connect()
        self._attributes = {}
        self._unique_id = None

        self._action(self._unique_id_command, self._set_unique_id)

        if self._value_template is not None:
            self._value_template.hass = hass

    @property
    def name(self):
        """Return the name of the sensor."""
        return self._name

    @property
    def icon(self):
        """Icon to use in the frontend, if any."""
        return 'mdi:folder-key-network'

    @property
    def state(self):
        """Return the state of the device."""
        return self._state

    @property
    def state_attributes(self):
        """Return the device state attributes."""
        return self._attributes

    @property
    def unit_of_measurement(self):
        """Return the unit of measurement of this entity, if any."""
        return self._unit_of_measurement

    @property
    def unique_id(self):
        """Return the unique id of this entity."""
        return self._unique_id

    @Throttle(MIN_TIME_BETWEEN_UPDATES)
    def update(self):
        self._action(self._command, self._update_state_with_value)
        _LOGGER.debug(self._state)

    def _action(self, command, value_handler_fn):
        from paramiko import ssh_exception
        value = None
        try:
            if not self._connected:
                self._connect()
            # If we still aren't connected at this point
            # don't try to send anything to the AP.
            if not self._connected:
                _LOGGER.warning("Still not connected - reporting nada.")
                return None
            stdin, stdout, stderr = self._ssh.exec_command(command)
            for line in stdout:
                value = line.strip('\n')

            if value is None:
                _LOGGER.warning("No return value was provided by command.")
                return None

            # Validate returned value string is not empty
            if len(value) < 1:
                _LOGGER.warning("Return value was empty.")
                return None

            value_handler_fn(value)

        except ssh_exception.SSHException as err:
            _LOGGER.error("Unexpected SSH error: %s", str(err))
            self._disconnect()
            return None
        except (AssertionError) as err:
            _LOGGER.error("Connection unavailable: %s", str(err))
            self._disconnect()
            return None

    def _update_state_with_value(self, value):
        if self._value_template is not None:
            self._state = self._value_template.render_with_possible_json_value(
                value, STATE_UNKNOWN)
        else:
            self._state = value

    def _set_unique_id(self, val):
        self._unique_id = format_mac(val)

    def _connect(self):
        """Connect to the SSH server."""
        from paramiko import ECDSAKey, SSHClient, ssh_exception
        from base64 import b64decode

        try:

            key = paramiko.ECDSAKey(data=base64.b64decode(self._key))
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.get_host_keys().add(self._host, 'ssh-rsa', key)
            if self._password is not None:
                _LOGGER.info("Using password as credential")
                client.connect(self._host, username=self._username, password=self._password)
            elif self._keyfile is not None:
                _LOGGER.info("Using keyfile as credential")
                client.connect(self._host, username=self._username, key_filename=self._keyfile, passphrase="")
            else:
                _LOGGER.error("No explicit client credential given")
                client.connect(self._host, username=self._username)

            self._ssh = client
            self._connected = True

        except ssh_exception.BadHostKeyException as err:
            _LOGGER.error("Host Key Mismatch: %s", str(err))
            self._disconnect()
            return None

        except:
            import traceback;
            _LOGGER.error("Connection refused. SSH enabled? %s", traceback.format_exc())
            self._disconnect()

    def _disconnect(self):
        """Disconnect the current SSH connection."""
        try:
            self._ssh.close()
        except Exception:
            pass
        finally:
            self._ssh = None

        self._connected = False


""" The Zyxel T50 modem """
""" I used these as a starting point: https://github.com/ThomasRinsma/vmg8825scripts """

import base64
import json
import logging

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
import requests

from .helpers import decrypt_response, encrypt_request

_LOGGER = logging.getLogger(__name__)


class ZyxelT50Modem:

    def __init__(self,
                 password=None,
                 host='192.168.1.1',
                 username='admin') -> None:
        self.url = host
        self.user = username
        self.password = password

        self.r = requests.Session()
        self.r.trust_env = False  # ignore proxy settings

        # we define the AesKey ourselves
        self.aes_key = b'\x42' * 32
        self.enc_aes_key = None
        self.sessionkey = None

        self._model = None
        self._sw_version = None
        self._unique_id = None

    def connect(self) -> None:
        """Set up a Zyxel modem."""
        self.enc_aes_key = self.__get_aes_key()

        try:
            self.__login()
        except CannotConnect as exp:
            _LOGGER.error("Failed to connect to modem")
            raise exp

        status = self.get_device_status()

        device_info = status["DeviceInfo"]
        if self._unique_id is None:
            self._unique_id = device_info["SerialNumber"]

        self._model = device_info["ModelName"]
        self._sw_version = device_info["SoftwareVersion"]

    def __get_aes_key(self):
        # ONCE
        # get pub key
        response = self.r.get(f"http://{self.url}/getRSAPublickKey")
        pubkey_str = response.json()['RSAPublicKey']

        # Encrypt the aes key with RSA pubkey of the device
        pubkey = RSA.import_key(pubkey_str)
        cipher_rsa = PKCS1_v1_5.new(pubkey)
        return cipher_rsa.encrypt(base64.b64encode(self.aes_key))

    def __login(self):
        login_data = {
            "Input_Account": self.user,
            "Input_Passwd": base64.b64encode(self.password.encode('ascii')).decode('ascii'),
            "RememberPassword": 0,
            "SHA512_password": False
        }

        enc_request = encrypt_request(self.aes_key, login_data)
        enc_request['key'] = base64.b64encode(self.enc_aes_key).decode('ascii')
        response = self.r.post(f"http://{self.url}/UserLogin", json.dumps(enc_request))
        decrypted_response = decrypt_response(self.aes_key, response.json())

        if decrypted_response is not None:
            response = json.loads(decrypted_response)

            self.sessionkey = response['sessionkey']
            return 'result' in response and response['result'] == 'ZCFG_SUCCESS'

        _LOGGER.error("Failed to decrypt response")
        raise CannotConnect

    def logout(self):
        response = self.r.post(f"http://{self.url}/cgi-bin/UserLogout?sessionKey={self.sessionkey}")
        response = response.json()

        if 'result' in response and response['result'] == 'ZCFG_SUCCESS':
            return True
        else:
            return False

    def __get_device_info(self, oid):
        response = self.r.get(f"http://{self.url}/cgi-bin/DAL?oid={oid}")
        decrypted_response = decrypt_response(self.aes_key, response.json())
        if decrypted_response is not None:
            json_string = decrypted_response.decode('utf8').replace("'", '"')
            json_data = json.loads(json_string)
            return json_data['Object'][0]

        _LOGGER.error("Failed to get device status")
        return None

    def get_device_status(self):
        result = self.__get_device_info("cardpage_status")
        if result is not None:
            return result

        _LOGGER.error("Failed to get device status")
        return None

    def get_connected_devices(self):
        result = self.__get_device_info("lanhosts")
        if result is not None:
            devices = {}
            for device in result['lanhosts']:
                devices[device['PhysAddress']] = {
                    "hostName": device['HostName'],
                    "physAddress": device['PhysAddress'],
                    "ipAddress": device['IPAddress'],
                }
            return devices

        _LOGGER.error("Failed to connected devices")
        return []


class CannotConnect(Exception):
    """Error to indicate we cannot connect."""

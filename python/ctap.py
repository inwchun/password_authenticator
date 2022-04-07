from fido2.hid import CtapHidDevice
from fido2.utils import sha256
from fido2.ctap1 import CTAP1, SignatureData
from fido2.cose import ES256
import sys
import struct
import hashlib
ITERATIONS=100_000

class HanPassSignatureData(SignatureData):
    def __init__(self, x):
        super().__init__(x)
        self.proof = self.signature

    def verify(self, app_param, client_param, public_key):
        """Verify the included signature with regard to the given app and client
        params, using the given public key.
        :param app_param: SHA256 hash of the app ID used for the request.
        :param client_param: SHA256 hash of the ClientData used for the request.
        :param public_key: Binary representation of the credential public key.
        """
        m = app_param + self[:5] + client_param
        sig_len = self.proof[1] + 2
        signature = self.proof[0: sig_len]
        random = self.proof[sig_len: sig_len + 32]
        hashval = self.proof[sig_len + 32:]
        k = None
        print(public_key)
        print(len(public_key))
        x = public_key[1:33]
        y = public_key[33:]
        for i in range(0, ITERATIONS):
            # convert i to 4 byte u8
            k_ = i.to_bytes(4, byteorder="big")
            if hashval == hashlib.sha256(m+random+k_).digest():
                k = k_
                break
        ES256.from_ctap1(public_key).verify(m+random+k+x+y, signature)

class HanPass(CTAP1):
    def __init__(
        self, device
    ):
        super().__init__(device)
    
    def authenticate(self, client_param, app_param, key_handle, check_only=False):
        """Authenticate a previously registered credential.
        :param client_param: SHA256 hash of the ClientData used for the request.
        :param app_param: SHA256 hash of the app ID used for the request.
        :param key_handle: The binary key handle of the credential.
        :param check_only: True to send a "check-only" request, which is used to
            determine if a key handle is known.
        :return: The authentication response from the authenticator.
        """
        data = (
            client_param + app_param + struct.pack(">B", len(key_handle)) + key_handle
        )
        p1 = 0x07 if check_only else 0x03
        response = self.send_apdu(ins=CTAP1.INS.AUTHENTICATE, p1=p1, data=data)
        return HanPassSignatureData(response)



dev = next(CtapHidDevice.list_devices(), None)
if not dev:
    print("No FIDO device found")
    sys.exit(1)

chal = sha256(b"AAA")
appid = sha256(b"BBB")

ctap1 = HanPass(dev)

print("version:", ctap1.get_version())

# True - make extended APDU and send it to key
# ISO 7816-3:2006. page 33, 12.1.3 Decoding conventions for command APDUs
# ISO 7816-3:2006. page 34, 12.2 Command-response pair transmission by T=0
# False - make group of short (less than 255 bytes length) APDU
# and send them to key. ISO 7816-3:2005, page 9, 5.1.1.1 Command chaining
dev.use_ext_apdu = False

reg = ctap1.register(chal, appid)
print("register:", reg)


reg.verify(appid, chal)
print("Register message verify OK")


auth = ctap1.authenticate(chal, appid, reg.key_handle)
print("authenticate result: ", auth)

res = auth.verify(appid, chal, reg.public_key)
print("Authenticate message verify OK")
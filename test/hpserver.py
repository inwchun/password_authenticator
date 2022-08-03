from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, WEBAUTHN_TYPE
from fido2.server import Fido2Server
from fido2.ctap import CtapError, STATUS
from fido2.utils import websafe_encode, websafe_decode
from base64 import b64decode
from getpass import getpass
from binascii import b2a_hex
from fido2.webauthn import (
    AttestationConveyancePreference,
    PublicKeyCredentialRpEntity,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType,
    PublicKeyCredentialParameters,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
    UserVerificationRequirement,
)
import hashlib
from cryptography.hazmat.primitives import constant_time
import sys
import ctypes

ITERATIONS = 4096
class HanPassServer(Fido2Server):
    def __init__(
        self, rp, attestation=None, verify_origin=None, verify_attestation=None
    ):
        super().__init__(rp, attestation, verify_origin, verify_attestation)

    def authenticate_complete(
        self, state, credentials, credential_id, client_data, auth_data, proof
    ):
        """Verify the correctness of the assertion data received from
        the client.
        :param state: The state data returned by the corresponding
            `register_begin`.
        :param credentials: The list of previously registered credentials.
        :param credential_id: The credential id from the client response.
        :param client_data: The client data.
        :param auth_data: The authenticator data.
        :param proof: The proof provided by the client."""
        if client_data.get("type") != WEBAUTHN_TYPE.GET_ASSERTION:
            raise ValueError("Incorrect type in ClientData.")
        if not self._verify(client_data.get("origin")):
            raise ValueError("Invalid origin in ClientData.")
        if websafe_decode(state["challenge"]) != client_data.challenge:
            raise ValueError("Wrong challenge in response.")
        if not constant_time.bytes_eq(self.rp.id_hash, auth_data.rp_id_hash):
            raise ValueError("Wrong RP ID hash in response.")
        if not auth_data.is_user_present():
            raise ValueError("User Present flag not set.")

        if (
            state["user_verification"] == UserVerificationRequirement.REQUIRED
            and not auth_data.is_user_verified()
        ):
            raise ValueError(
                "User verification required, but user verified flag not set."
            )

        for cred in credentials:
            if cred.credential_id == credential_id:
                sig_len = proof[1] + 2
                signature = proof[0: sig_len]
                t_vk = proof[sig_len: sig_len + 32]
                r = proof[sig_len + 32:]
                p = None
                m = auth_data + client_data.hash
                x = cred.public_key[-2]
                y = cred.public_key[-3]
                for i in range(0, ITERATIONS):
                    # convert i to 4 byte u8
                    p_ = i.to_bytes(2, byteorder="big")
                    # print(p_)
                    if t_vk == hashlib.pbkdf2_hmac('sha256',x+y+p_,r,25):
                        # p = p_
                        try:
                            cred.public_key.verify(hashlib.pbkdf2_hmac('sha256',m+x+y+p_,r,25), signature)
                        except _InvalidSignature:
                            continue
                        return cred

        raise ValueError("Unknown credential ID.")



# def on_keepalive(status):
#     if status == STATUS.UPNEEDED:  # Waiting for touch
#         print("\nTouch your authenticator device now...\n")

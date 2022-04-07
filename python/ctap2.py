
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
ITERATIONS = 100_000

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
                random = proof[sig_len: sig_len + 32]
                hashval = proof[sig_len + 32:]
                k = None
                m = auth_data + client_data.hash
                x = cred.public_key[-2]
                y = cred.public_key[-3]
                for i in range(0, ITERATIONS):
                    # convert i to 4 byte u8
                    k_ = i.to_bytes(4, byteorder="big")
                    if hashval == hashlib.sha256(m+random+k_).digest():
                        k = k_
                        break
                try:
                    cred.public_key.verify(m + random + k + x + y, signature)
                except _InvalidSignature:
                    raise ValueError("Invalid signature.")

                return cred
        raise ValueError("Unknown credential ID.")



def on_keepalive(status):
    if status == STATUS.UPNEEDED:  # Waiting for touch
        print("\nTouch your authenticator device now...\n")

# Locate a device
dev = next(CtapHidDevice.list_devices(), None)

if dev is None:
    print("No FIDO device found")
    sys.exit(1)

# Set up a FIDO 2 client using the origin https://example.com
client = Fido2Client(dev, "https://example.com")

server = HanPassServer(
    {"id": "example.com", "name": "Example RP"},
    attestation="none",
)

user = {"id": b"user_id", "name": "A. User"}
print(client.info)

# Prepare parameters for makeCredential
create_options, state = server.register_begin(
    user,
    user_verification="discouraged",
    authenticator_attachment="cross-platform"
)

# Create user credential
result = client.make_credential(create_options["publicKey"], on_keepalive=on_keepalive)

# Complete registration
auth_data = server.register_complete(
    state, result.client_data, result.attestation_object
)


credentials = [auth_data.credential_data]


print("New credential created!")

print("CLIENT DATA:", result.client_data)
print("ATTESTATION OBJECT:", result.attestation_object)
print()
print("CREDENTIAL DATA:", auth_data.credential_data)


# Prepare parameters for getAssertion
request_options, state = server.authenticate_begin(credentials, user_verification="discouraged")

# Authenticate the credential
result = client.get_assertion(
    request_options["publicKey"], on_keepalive=on_keepalive
)

# Only one cred in allowCredentials, only one response.
result = result.get_response(0)

# Complete authenticator
server.authenticate_complete(
    state,
    credentials,
    result.credential_id,
    result.client_data,
    result.authenticator_data,
    result.signature,
)

print("Credential authenticated!")

print("CLIENT DATA:", result.client_data)
print()
print("AUTH DATA:", result.authenticator_data)

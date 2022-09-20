from hpserver import HanPassServer
from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client
import os
import time

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

print(create_options)

# Create user credential
result = client.make_credential(create_options["publicKey"])

# Complete registration
auth_data = server.register_complete(
    state, result.client_data, result.attestation_object
)


credentials = [auth_data.credential_data]

print("Credential created!")

request_options, state = server.authenticate_begin(credentials, user_verification="discouraged")

print(request_options['publicKey'])
# Authenticate the credential

# result = client.get_assertion(
#     request_options["publicKey"]
# )

# Authenticate the credential
result = client.get_assertion(
    request_options["publicKey"]
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

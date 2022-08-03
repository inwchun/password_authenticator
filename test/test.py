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

# Create user credential
result = client.make_credential(create_options["publicKey"])

# Complete registration
auth_data = server.register_complete(
    state, result.client_data, result.attestation_object
)


credentials = [auth_data.credential_data]


print("Credential created!")

f = open("result/test.txt", "a")

for i in range(2):
    request_options, state = server.authenticate_begin(credentials, user_verification="discouraged")
    request_options['publicKey']['allowCredentials'][0]['id'] = os.urandom(32)
    print(request_options['publicKey'])
    # Authenticate the credential
    start = time.time()
    result = client.get_assertion(
        request_options["publicKey"]
    )
    end = time.time()
    f.write(str(end-start) + "\n")
    print(i, result)

f.close()
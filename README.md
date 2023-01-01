# Password Authenticator

An academic proof-of-concept prototype enabling secure password-based authentication through WebAuthn.
This software authenticator follows the WebAuthn and CTAP2 standardizations, and supports a reliable interface to receive user passwords. (currently connected by USBIP)

# Use

Insert vhci-hcd module.
```sudo modprobe vhci-hcd```

Run the authenticator as a listening server.
```
cargo run
```

Connect to the module.
```sudo usbip attach -r 127.0.0.1 -d 1-1```

# Testing

## Test with python code 

python3 test/ctap2.py

## Test with browser

<s>https://sflab.snu.ac.kr:89 create and login.
Warning: Firefox does not support FIDO2 yet</s>

The website is currently down.


# References
[WebAuthn](https://www.w3.org/TR/webauthn-2/)

[CTAP2](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)

[SoftFido](https://github.com/ellerh/softfido)

[OpenSK](https://github.com/google/OpenSK)


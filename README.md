# HanPass Authenticator

academic proof-of-concept prototype for replacement of the current password authentication system using WebAuthn.
The HanPass Authenticator implements a software authenticator connected via CTAP2 (connected by USBIP).

# Use

Insert vhci-hcd module.
```sudo modprobe vhci-hcd```

Run the HanPass authenticator as a listening server.
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

Currently the website is down.


# References
[WebAuthn](https://www.w3.org/TR/webauthn-2/)

[CTAP2](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)

[SoftFido](https://github.com/ellerh/softfido)

[OpenSK](https://github.com/google/OpenSK)


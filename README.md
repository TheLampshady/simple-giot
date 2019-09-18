# Simple Google IoT Core 
A simple base class for connecting an IoT Core device.

# Setup
```bash
pip install git+https://github.com/TheLampshady/simple-giot.git
```

# IoT Core
Install and create certs for authentication with IoT Core

Google CA cert
```bash
curl -O https://pki.goog/roots.pem 
```

Public / Private Cert
```bash
openssl genrsa -out rsa_private.pem 2048 && \\
openssl rsa -in rsa_private.pem -pubout -out rsa_public.pem && \\
cat rsa_public.pem
```

## Example

### Extend Class
Create a class and override callback functions.

```python
from simple_giot.iot_core_device import Client

class MyClient(Client):

    def __init__(self, new_arg, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.service = new_arg

    def on_connect(self, unused_client, unused_userdata, unused_flags, rc):
        super().on_connect(unused_client, unused_userdata, unused_flags, rc)
        print('Success!!!!')

    def process_config(self, payload):
        self.service.run(payload)
```

### 




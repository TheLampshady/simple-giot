# Simple Google IoT Core 
A simple base class for connecting an IoT Core device.

# Setup
```bash
pip install git+https://github.com/TheLampshady/simple-giot.git
```


## Example
Create a class and override callback functions.

```python
from simple_giot.iot_core_device import Client

class MyClient(Client):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.test = 1

    def on_connect(self, unused_client, unused_userdata, unused_flags, rc):
        super().on_connect(unused_client, unused_userdata, unused_flags, rc)
        print('Success!!!!')
```

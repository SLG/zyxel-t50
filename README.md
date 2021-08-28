# Zyxel T50
A small wrapper for the Zyxel T50 modem.

It can retrieve basic status of the modem and a list of connected devices.
This is used for a [device tracking integration](https://github.com/home-assistant/core/tree/dev/homeassistant/components/zyxelt50) of [Home Assistant](https://www.home-assistant.io/).

# Simple example
```python
import json
from zyxelt50.modem import ZyxelT50Modem


router = ZyxelT50Modem('#YOUR ADMIN PASSWORD#')
router.connect()

status = router.get_connected_devices()
print(json.dumps(status, indent=4))

```

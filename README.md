# aioradius

**aioradius** is an asyncio implementation of RADIUS protocol. 
It contain basic implementation for RADIUS server and client.

### Implementation of RADIUS server
For create your **RADIUS server** implementation, you must inherit `AbstractRadiusServer` 
and implement its abstract method
`AbstractRadiusServer.validate_nas(self, remote_addr)`
    
    Validate access for NAS and get shared_key
    Params:
        remote_addr - tuple(pair) of remote hostname and remote_port
    Return:
        shared_secret - shared secret between NAS and server
    Raise:
        RadiusResponseError if NAS is not valid

and overwrite at least one method from `handle_auth_packet`, `handle_acc_packet`.


If your server must handle *Access-Request* packets, you must overwrite method:
`AbstractRadiusServer.handle_auth_packet(self, request_attributes)`

    Handle Access-Request packet and generate response
    Params:
        request_attributes - instance of aioradius.packet.AttributesSet
    Return:
       (
          response_attributes - iterable of pairs (AttributeName, AttributeValue)
          response_code - any of ACCESS_ACCEPT, ACCESS_REJECT, ACCESS_CHALLENGE
       )
    Raise:
       RadiusResponseError

If your server must handle *Accounting-Request* packets, you must overwrite method:
`AbstractRadiusServer.handle_acc_packet(self, request_attributes)`

    Handle Accounting-Request packet and generate response
    Params:
       request_attributes - instance of `AttributesSet`
    Return:
       (
          response_attributes - iterable of pairs (AttributeName, AttributeValue),
          None
       )
    Raise:
       RadiusResponseError

For example:
```python
from aioradius import AbstractRadiusServer

class AuthOnlyRadiusServer(AbstractRadiusServer):
    def validate_nas(self, remote_addr):
        <your code here>

    @asyncio.coroutine
    def handle_auth_packet(self, request_attributes):
        <your code here>
```

Implementation of methods can be a simple method or asyncio coroutine.

If method implementation is a simple method, it executed at basic asyncio executor 
(with `run_in_executor` method of asyncio event loop)

Also you can overwrite method 
`AbstractRadiusServer.register_handle_exception(self, exc)` 
for own action when exception is raised at handle process.

You server can implement simple function or asyncio.coroutine for its periodic calling.
Special method decorator `periodic_task` used for this.

For example:

```python
from aioradius import periodic_task, AbstractRadiusServer

class RealRadiusServer(AbstractRadiusServer):
    def nas_validation(self, received_data, remote_addr):
        <your code here>

    def handle_acc_packet(self, session_id, request_attributes):
        <your code here>

    @asyncio.coroutine
    def handle_auth_packet(self, session_id, request_attributes):
        <your code here>

    @periodic_task(delay=5) # It create periodic task with 5 sec calling period
    def your_periodic_task(self):
        <your code here>
```

For instantiate server you must set IP-address or hostname, where server will listen.
Optional arguments:
- `auth_port` - port number, where server will listen for Access-Request packets, default 1812
- `acc_port` - port number, where server will listen for Accounting-Request packets, default 1813
- `loop` - usable asyncio event loop

```python
if __name__ == '__main__':
    server = RealRadiusServer('localhost')
    server.run()
```
---
### Client usage with asyncio event loop

Initialize client and create RADIUS packet
```python
import asyncio
from aioradius import RadiusClient, packet

# Initialize client
event_loop = asyncio.get_event_loop()
client = RadiusClient(event_loop)

# Initialize RADIUS packet
request = packet.AccessRequest('SHARED_SECRET')
# If need adding attributes to packet:
request.add_attributes(
    ('User-Name', 'username'),
    ('User-Password', 'password')
)
```

Then we are send packet and create response future, that will be done when server send response
Method `send_packet` is an asyncio.coroutine and if need it async create new endpoint

```python
response_future =  event_loop.run_until_complete(
    client.send_packet(
        request,
        remote_host = 'server.radius', # If not set will be used client.default_server
        remote_port = 1812 # If not set will be used client.default_port
    )
)
# Then we are wait while response_future is done
event_loop.run_until_complete(response_future)

# When it is done trying to get results
try:
    response, response_time = response_future.result()
except Exception as e:
    print("Response is not received, ", str(e))
```
Don`t forget close client, when need
```python
client.close()
```
---
### Client usage from asyncio coroutine
Initialize client
```python
import asyncio
from aioradius import RadiusClient, packet

event_loop = asyncio.get_event_loop()
client = RadiusClient(event_loop, default_server='localhost', 
                      default_port=1812, client_identifier='blafoo')
```
Define asyncio coroutine, that used client
```python
@asyncio.coroutine
def coro(client):
    # Initialize RADIUS packet
    request = packet.AccessRequest('SHARED_SECRET')
    # If need adding attributes to packet:
    requests.add_attributes(
        ('User-Name', 'username'),
        ('User-Password', 'password')
    )
    response_future = yield from client.send_packet(request)
    response, response_time = yield from response_future
```
or
```python
async def coro(client):
    # Initialize RADIUS packet
    request = packet.AccessRequest('SHARED_SECRET')
    # If need adding attributes to packet:
    requests.add_attributes(
        ('User-Name', 'username'),
        ('User-Password', 'password')
    )
    response_future = await client.send_packet(request)
    response, response_time = await response_future
```
And run this coroutine at event loop
```python
event_loop.run_until_complete(coro(client))
```
Don`t forget close client, when need
```python
client.close()
```

Requirements
---
- bidict
- ipaddress
- expiringdict
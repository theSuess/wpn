# wpn
Easy to use websocket VPN

### WTF is this?
wpn is a VPN solution using websockets as transport layer. Usefull when running behind a reverse proxy like nginx.
There are some other websocket-vpns but wpn aims for usability.
### Setup

```.bash
# On both
go get -u github.com/theSuess/wpn

# On the server
wpn --debug server -l 0.0.0.0:6969 --client-network 192.168.69.0/24 --range 192.168.69.150-192.168.69.160

# On the client
wpn --debug -r <server-ip>:6969
```
Now the client can reach every device in the `192.168.69.0/24` network

### Platform support
wpn is only available for linux at the moment. Contributions to add support for Windows,Mac or BSD are welcomed.

### How secure is this?
When not using secure websockets (wss) the security is basically nil. Otherwise the encryption of the same strength as HTTPS.
Authorization can be set with the `--secret` parameter and allows for some kind of access restriction.

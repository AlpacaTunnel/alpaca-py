# alpaca-py

A Python re-implementation of alpaca-tunnel. Last version compatible with alpaca-tunnel is v1.0, header changed after that.

## Branches

Branch full-header: keep src/dst-inside mark, and TTL.

Branch plain-text: remove encryption to improve performance, also removed some items in header.

Branch master: still uses AES encryption, but removed ICV, and uses a simplified header.

## Header change

To improve performance, only left the most important items in header.

Removed src/dst-inside mark, so we can not do NAT, and all peers must use the same tunnel network.

Also removed TTL, so there may be infinite loop between forwarders. However, if the looped packet re-enter a peer within 3 seconds, it will be treated as duplicated and droped. So this is not a big problem.

## Security Warnings

This software is not designed by an security expert, and not designed for strong security. It uses static pre-shared-keys, so there is no perfect forward secrecy, and it's vulnerable to replay attack. Don't rely on it.

A peer may forge as any other peer in the same group, and receive all packets sent to this peer. Because there is only encryption without authentication, the server will store any address claimed as some peer.

The AES encryption is not intended to be secure, but simple obfuscation. Even XOR can be used, but XOR is even slower than AES?

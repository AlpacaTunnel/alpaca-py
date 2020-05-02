# alpaca-py

A Python re-implementation of alpaca-tunnel. Last version compatible with alpaca-tunnel is v1.0, header changed after that.

Branch plain-text: remove encryption to improve performance, also removed some items in header.

Branch no-icv: still uses AES encryption, but removed ICV, and uses a simplified header.

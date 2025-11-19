# AetherPacket

Enterprise-grade userspace network appliance built in pure Ruby for raw socket performance.

## Features

- Direct PF_PACKET socket interface for wire-level access
- Layer 2/3 transparent bridge and router functionality  
- Stateful connection tracking and NAT
- Enterprise security features (firewall, IDS, rate limiting)
- Minimal allocations for high-performance packet processing

## Requirements

- Linux (required for PF_PACKET sockets)
- Ruby 3.0+
- Root privileges (for raw socket access)

## Installation

```bash
bundle install
```

## Usage

```ruby
require 'aether_packet'

# Coming soon...
```

## Architecture

AetherPacket implements a modular packet processing pipeline:

1. **Link Layer**: Ethernet frame parsing and MAC learning
2. **Network Layer**: IPv4/ARP processing and routing  
3. **Transport Layer**: TCP/UDP parsing and connection tracking
4. **Security Layer**: Stateful firewall and traffic shaping
5. **Application Layer**: DNS inspection and protocol analysis

## Performance

Built for minimal object allocation in hot paths using:
- Direct binary parsing with BinData
- Buffer pooling and zero-copy operations
- Efficient data structures (Radix trees, hash tables)

## License

MIT
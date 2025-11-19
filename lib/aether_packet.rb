# frozen_string_literal: true

# AetherPacket - Enterprise-grade userspace network appliance
# Built for raw socket performance and minimal allocations
module AetherPacket
  VERSION = "0.1.0"
  
  # Base error class for all AetherPacket exceptions
  class Error < StandardError
    attr_reader :context

    def initialize(message = nil, context: {})
      super(message)
      @context = context
    end
  end

  # Network layer errors
  class NetworkError < Error; end
  class InterfaceError < NetworkError; end
  class SocketError < NetworkError; end
  class PacketError < NetworkError; end
  
  # Protocol layer errors  
  class ProtocolError < Error; end
  class ChecksumError < ProtocolError; end
  class MalformedPacketError < ProtocolError; end
  
  # System layer errors
  class SystemError < Error; end
  class PermissionError < SystemError; end
  class ResourceError < SystemError; end
end

# Autoload core components
require_relative "aether_packet/version"
require_relative "aether_packet/network_interface"
require_relative "aether_packet/promiscuous_mode"
require_relative "aether_packet/packet_reactor"
require_relative "aether_packet/ethernet_frame"
require_relative "aether_packet/ipv4_packet"
require_relative "aether_packet/arp_protocol"
require_relative "aether_packet/routing_table"
require_relative "aether_packet/packet_forwarder"
require_relative "aether_packet/icmp_protocol"
require_relative "aether_packet/udp_datagram"
require_relative "aether_packet/tcp_segment"
require_relative "aether_packet/connection_table"
require_relative "aether_packet/tcp_state_tracker"
require_relative "aether_packet/nat_engine"
require_relative "aether_packet/stateful_nat_engine"
require_relative "aether_packet/network_appliance"
require_relative "aether_packet/firewall"
require_relative "aether_packet/stateful_firewall"
require_relative "aether_packet/token_bucket"
require_relative "aether_packet/traffic_shaper"
# frozen_string_literal: true

require "bindata"

module AetherPacket
  # IcmpPacket parses and creates ICMP messages per RFC 792
  # Supports Echo Request/Reply and various error messages
  class IcmpPacket < BinData::Record
    # ICMP Message Types
    TYPE_ECHO_REPLY = 0
    TYPE_DEST_UNREACHABLE = 3
    TYPE_SOURCE_QUENCH = 4
    TYPE_REDIRECT = 5
    TYPE_ECHO_REQUEST = 8
    TYPE_TIME_EXCEEDED = 11
    TYPE_PARAMETER_PROBLEM = 12
    TYPE_TIMESTAMP_REQUEST = 13
    TYPE_TIMESTAMP_REPLY = 14

    # ICMP Destination Unreachable Codes
    CODE_NET_UNREACHABLE = 0
    CODE_HOST_UNREACHABLE = 1
    CODE_PROTOCOL_UNREACHABLE = 2
    CODE_PORT_UNREACHABLE = 3
    CODE_FRAGMENTATION_NEEDED = 4
    CODE_SOURCE_ROUTE_FAILED = 5

    # ICMP Time Exceeded Codes
    CODE_TTL_EXCEEDED = 0
    CODE_FRAGMENT_TIMEOUT = 1

    uint8 :type           # ICMP message type
    uint8 :code           # ICMP message code
    uint16be :checksum    # ICMP checksum
    uint32be :rest_of_header  # Varies by ICMP type
    rest :data            # ICMP data payload

    # Parse raw ICMP packet data
    def self.parse(raw_data)
      begin
        packet = new
        packet.read(raw_data)
        packet.validate!
        packet
      rescue BinData::ValidityError => e
        raise MalformedPacketError, "Invalid ICMP packet: #{e.message}"
      end
    end

    # Validate ICMP packet
    def validate!
      raise MalformedPacketError, "ICMP packet too small" if num_bytes < 8
      validate_checksum!
    end

    # Check if this is an Echo Request (ping)
    def echo_request?
      type == TYPE_ECHO_REQUEST
    end

    # Check if this is an Echo Reply (pong)
    def echo_reply?
      type == TYPE_ECHO_REPLY
    end

    # Check if this is an error message
    def error_message?
      [TYPE_DEST_UNREACHABLE, TYPE_SOURCE_QUENCH, TYPE_TIME_EXCEEDED, TYPE_PARAMETER_PROBLEM].include?(type)
    end

    # Get ICMP type name
    def type_name
      case type
      when TYPE_ECHO_REPLY then :echo_reply
      when TYPE_DEST_UNREACHABLE then :dest_unreachable
      when TYPE_SOURCE_QUENCH then :source_quench
      when TYPE_REDIRECT then :redirect
      when TYPE_ECHO_REQUEST then :echo_request
      when TYPE_TIME_EXCEEDED then :time_exceeded
      when TYPE_PARAMETER_PROBLEM then :parameter_problem
      when TYPE_TIMESTAMP_REQUEST then :timestamp_request
      when TYPE_TIMESTAMP_REPLY then :timestamp_reply
      else :unknown
      end
    end

    # Get Echo Request/Reply fields
    def echo_identifier
      return nil unless echo_request? || echo_reply?
      (rest_of_header >> 16) & 0xffff
    end

    def echo_sequence
      return nil unless echo_request? || echo_reply?
      rest_of_header & 0xffff
    end

    # Calculate ICMP checksum
    def calculate_checksum
      # Create packet data with checksum field zeroed
      packet_data = to_binary_s
      packet_bytes = packet_data.unpack("C*")
      
      # Zero out checksum field (bytes 2-3)
      packet_bytes[2] = 0
      packet_bytes[3] = 0
      
      # Pad to even length if necessary
      packet_bytes << 0 if packet_bytes.length.odd?
      
      # Calculate checksum over 16-bit words
      sum = 0
      packet_bytes.each_slice(2) do |high, low|
        sum += (high << 8) + (low || 0)
      end
      
      # Add carry bits
      while (sum >> 16) > 0
        sum = (sum & 0xffff) + (sum >> 16)
      end
      
      # Return one's complement
      ~sum & 0xffff
    end

    # Validate checksum
    def validate_checksum!
      calculated = calculate_checksum
      raise ChecksumError, "Invalid ICMP checksum: expected #{calculated.to_s(16)}, got #{checksum.to_s(16)}" unless calculated == checksum
    end

    # Update checksum field
    def update_checksum!
      self.checksum = 0
      self.checksum = calculate_checksum
    end

    # Create Echo Request (ping)
    def self.create_echo_request(identifier:, sequence:, data: "")
      packet = new
      packet.type = TYPE_ECHO_REQUEST
      packet.code = 0
      packet.rest_of_header = (identifier << 16) | sequence
      packet.data = data
      packet.update_checksum!
      packet
    end

    # Create Echo Reply (pong)
    def self.create_echo_reply(identifier:, sequence:, data: "")
      packet = new
      packet.type = TYPE_ECHO_REPLY
      packet.code = 0
      packet.rest_of_header = (identifier << 16) | sequence
      packet.data = data
      packet.update_checksum!
      packet
    end

    # Create Destination Unreachable message
    def self.create_dest_unreachable(code:, original_packet_data:)
      packet = new
      packet.type = TYPE_DEST_UNREACHABLE
      packet.code = code
      packet.rest_of_header = 0  # Unused field
      packet.data = original_packet_data[0, 28]  # IP header + 8 bytes of data
      packet.update_checksum!
      packet
    end

    # Create Time Exceeded message
    def self.create_time_exceeded(code:, original_packet_data:)
      packet = new
      packet.type = TYPE_TIME_EXCEEDED
      packet.code = code
      packet.rest_of_header = 0  # Unused field
      packet.data = original_packet_data[0, 28]  # IP header + 8 bytes of data
      packet.update_checksum!
      packet
    end

    # Extract packet metadata
    def metadata
      meta = {
        type: type,
        type_name: type_name,
        code: code,
        checksum: checksum,
        data_size: data.bytesize
      }

      # Add type-specific fields
      if echo_request? || echo_reply?
        meta[:identifier] = echo_identifier
        meta[:sequence] = echo_sequence
      end

      meta
    end
  end

  # IcmpProtocol handles ICMP message processing and generation
  # Implements ping response and error message generation
  class IcmpProtocol
    attr_reader :stats

    def initialize
      @stats = {
        echo_requests_received: 0,
        echo_replies_sent: 0,
        error_messages_sent: 0,
        malformed_packets: 0,
        last_reset: Time.now
      }
    end

    # Process incoming ICMP packet
    def process_packet(icmp_packet, source_ip, destination_ip, interface_info)
      case icmp_packet.type
      when IcmpPacket::TYPE_ECHO_REQUEST
        process_ping_request(icmp_packet, source_ip, destination_ip, interface_info)
      when IcmpPacket::TYPE_ECHO_REPLY
        process_ping_reply(icmp_packet, source_ip, destination_ip)
      else
        # Other ICMP types are handled but not actively processed
        nil
      end
    rescue MalformedPacketError, ChecksumError
      @stats[:malformed_packets] += 1
      nil
    end

    # Process ICMP Echo Request and generate reply
    def process_ping_request(ping_request, source_ip, destination_ip, interface_info)
      @stats[:echo_requests_received] += 1

      # Create Echo Reply with same identifier, sequence, and data
      ping_reply = IcmpPacket.create_echo_reply(
        identifier: ping_request.echo_identifier,
        sequence: ping_request.echo_sequence,
        data: ping_request.data
      )

      # Create IPv4 packet for reply
      ip_reply = IPv4Packet.create(
        source_ip: destination_ip,
        destination_ip: source_ip,
        protocol: IPv4Packet::PROTO_ICMP,
        payload: ping_reply.to_binary_s
      )

      # Determine destination MAC address
      dest_mac = resolve_destination_mac(source_ip, interface_info)
      return nil unless dest_mac

      # Create Ethernet frame
      eth_frame = EthernetFrame.create(
        destination_mac: dest_mac,
        source_mac: interface_info[:mac_address],
        ethertype: EthernetFrame::ETHERTYPE_IPv4,
        payload: ip_reply.to_binary_s
      )

      @stats[:echo_replies_sent] += 1

      {
        action: :ping_reply,
        frame_data: eth_frame.to_binary_s,
        identifier: ping_request.echo_identifier,
        sequence: ping_request.echo_sequence
      }
    end

    # Process ICMP Echo Reply (informational)
    def process_ping_reply(ping_reply, source_ip, destination_ip)
      {
        action: :ping_reply_received,
        source_ip: source_ip,
        identifier: ping_reply.echo_identifier,
        sequence: ping_reply.echo_sequence,
        data_size: ping_reply.data.bytesize
      }
    end

    # Generate ICMP Destination Unreachable message
    def generate_dest_unreachable(reason:, original_ip_packet:, source_interface_info:)
      code = case reason
      when :net_unreachable then IcmpPacket::CODE_NET_UNREACHABLE
      when :host_unreachable then IcmpPacket::CODE_HOST_UNREACHABLE
      when :protocol_unreachable then IcmpPacket::CODE_PROTOCOL_UNREACHABLE
      when :port_unreachable then IcmpPacket::CODE_PORT_UNREACHABLE
      when :fragmentation_needed then IcmpPacket::CODE_FRAGMENTATION_NEEDED
      else IcmpPacket::CODE_HOST_UNREACHABLE
      end

      icmp_packet = IcmpPacket.create_dest_unreachable(
        code: code,
        original_packet_data: original_ip_packet.to_binary_s
      )

      create_error_response(icmp_packet, original_ip_packet, source_interface_info)
    end

    # Generate ICMP Time Exceeded message
    def generate_time_exceeded(reason:, original_ip_packet:, source_interface_info:)
      code = case reason
      when :ttl_exceeded then IcmpPacket::CODE_TTL_EXCEEDED
      when :fragment_timeout then IcmpPacket::CODE_FRAGMENT_TIMEOUT
      else IcmpPacket::CODE_TTL_EXCEEDED
      end

      icmp_packet = IcmpPacket.create_time_exceeded(
        code: code,
        original_packet_data: original_ip_packet.to_binary_s
      )

      create_error_response(icmp_packet, original_ip_packet, source_interface_info)
    end

    # Get ICMP statistics
    def icmp_stats
      now = Time.now
      duration = now - @stats[:last_reset]

      @stats.merge(
        duration: duration,
        ping_rate: duration > 0 ? @stats[:echo_requests_received] / duration : 0,
        error_rate: duration > 0 ? @stats[:error_messages_sent] / duration : 0
      )
    end

    # Reset statistics
    def reset_stats!
      @stats.each_key { |key| @stats[key] = 0 unless key == :last_reset }
      @stats[:last_reset] = Time.now
    end

    private

    # Create ICMP error response packet
    def create_error_response(icmp_packet, original_ip_packet, interface_info)
      # Get our IP address for this interface
      our_ip = interface_info[:ip_address]
      return nil unless our_ip

      # Create IPv4 packet for ICMP error
      ip_packet = IPv4Packet.create(
        source_ip: our_ip,
        destination_ip: original_ip_packet.source_ip_string,
        protocol: IPv4Packet::PROTO_ICMP,
        payload: icmp_packet.to_binary_s
      )

      # Resolve destination MAC
      dest_mac = resolve_destination_mac(original_ip_packet.source_ip_string, interface_info)
      return nil unless dest_mac

      # Create Ethernet frame
      eth_frame = EthernetFrame.create(
        destination_mac: dest_mac,
        source_mac: interface_info[:mac_address],
        ethertype: EthernetFrame::ETHERTYPE_IPv4,
        payload: ip_packet.to_binary_s
      )

      @stats[:error_messages_sent] += 1

      {
        action: :icmp_error,
        type: icmp_packet.type_name,
        code: icmp_packet.code,
        frame_data: eth_frame.to_binary_s
      }
    end

    # Resolve destination MAC address (placeholder - would use ARP)
    def resolve_destination_mac(ip_address, interface_info)
      # In a real implementation, this would:
      # 1. Check ARP cache
      # 2. Send ARP request if needed
      # 3. Queue packet if ARP resolution pending
      # For now, return a placeholder
      "00:00:00:00:00:00"
    end
  end
end
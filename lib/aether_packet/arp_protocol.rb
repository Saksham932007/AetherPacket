# frozen_string_literal: true

require "bindata"

module AetherPacket
  # ArpPacket handles Address Resolution Protocol (RFC 826)
  # Provides MAC-to-IP address mapping for IPv4 networks
  class ArpPacket < BinData::Record
    # ARP Hardware Types
    HTYPE_ETHERNET = 1
    
    # ARP Protocol Types
    PTYPE_IPV4 = 0x0800
    
    # ARP Operations
    OP_REQUEST = 1
    OP_REPLY = 2
    OP_RARP_REQUEST = 3
    OP_RARP_REPLY = 4

    uint16be :hardware_type    # Hardware address type
    uint16be :protocol_type    # Protocol address type  
    uint8 :hardware_length     # Hardware address length
    uint8 :protocol_length     # Protocol address length
    uint16be :operation        # ARP operation
    array :sender_mac, type: :uint8, initial_length: 6      # Sender hardware address
    uint32be :sender_ip        # Sender protocol address
    array :target_mac, type: :uint8, initial_length: 6      # Target hardware address
    uint32be :target_ip        # Target protocol address

    # Parse raw ARP packet data
    def self.parse(raw_data)
      begin
        packet = new
        packet.read(raw_data)
        packet.validate!
        packet
      rescue BinData::ValidityError => e
        raise MalformedPacketError, "Invalid ARP packet: #{e.message}"
      end
    end

    # Validate ARP packet
    def validate!
      raise MalformedPacketError, "Invalid hardware type" unless hardware_type == HTYPE_ETHERNET
      raise MalformedPacketError, "Invalid protocol type" unless protocol_type == PTYPE_IPV4
      raise MalformedPacketError, "Invalid hardware length" unless hardware_length == 6
      raise MalformedPacketError, "Invalid protocol length" unless protocol_length == 4
      raise MalformedPacketError, "Invalid operation" unless [OP_REQUEST, OP_REPLY].include?(operation)
    end

    # Check if this is an ARP request
    def request?
      operation == OP_REQUEST
    end

    # Check if this is an ARP reply
    def reply?
      operation == OP_REPLY
    end

    # Get sender MAC as string
    def sender_mac_string
      sender_mac.map { |byte| format("%02x", byte) }.join(":")
    end

    # Get target MAC as string
    def target_mac_string  
      target_mac.map { |byte| format("%02x", byte) }.join(":")
    end

    # Get sender IP as string
    def sender_ip_string
      ip_to_string(sender_ip)
    end

    # Get target IP as string
    def target_ip_string
      ip_to_string(target_ip)
    end

    # Create ARP request
    def self.create_request(sender_mac:, sender_ip:, target_ip:)
      packet = new
      packet.hardware_type = HTYPE_ETHERNET
      packet.protocol_type = PTYPE_IPV4
      packet.hardware_length = 6
      packet.protocol_length = 4
      packet.operation = OP_REQUEST
      packet.sender_mac = parse_mac_address(sender_mac)
      packet.sender_ip = string_to_ip(sender_ip)
      packet.target_mac = [0, 0, 0, 0, 0, 0]  # Unknown in request
      packet.target_ip = string_to_ip(target_ip)
      packet
    end

    # Create ARP reply
    def self.create_reply(sender_mac:, sender_ip:, target_mac:, target_ip:)
      packet = new
      packet.hardware_type = HTYPE_ETHERNET
      packet.protocol_type = PTYPE_IPV4
      packet.hardware_length = 6
      packet.protocol_length = 4
      packet.operation = OP_REPLY
      packet.sender_mac = parse_mac_address(sender_mac)
      packet.sender_ip = string_to_ip(sender_ip)
      packet.target_mac = parse_mac_address(target_mac)
      packet.target_ip = string_to_ip(target_ip)
      packet
    end

    # Extract packet metadata
    def metadata
      {
        hardware_type: hardware_type,
        protocol_type: protocol_type,
        operation: operation,
        operation_name: operation == OP_REQUEST ? :request : :reply,
        sender_mac: sender_mac_string,
        sender_ip: sender_ip_string,
        target_mac: target_mac_string,
        target_ip: target_ip_string
      }
    end

    private

    # Convert 32-bit integer to IP string
    def ip_to_string(ip_int)
      [(ip_int >> 24) & 0xff, (ip_int >> 16) & 0xff, (ip_int >> 8) & 0xff, ip_int & 0xff].join(".")
    end

    # Convert IP string to 32-bit integer
    def self.string_to_ip(ip_string)
      octets = ip_string.split(".").map(&:to_i)
      raise ArgumentError, "Invalid IP address" unless octets.length == 4 && octets.all? { |o| o >= 0 && o <= 255 }
      
      (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
    end

    # Parse MAC address string to byte array
    def self.parse_mac_address(mac_string)
      if mac_string.is_a?(String)
        mac_string.split(":").map { |hex| hex.to_i(16) }
      elsif mac_string.is_a?(Array)
        mac_string
      else
        raise ArgumentError, "Invalid MAC address format"
      end
    end
  end

  # ArpProtocol handles ARP request/reply processing
  # Maintains ARP cache and responds to requests for configured IPs
  class ArpProtocol
    attr_reader :arp_cache, :virtual_ips

    def initialize
      @arp_cache = {}  # IP -> MAC mapping
      @virtual_ips = {}  # Our IP -> MAC mappings
      @arp_cache_timeout = 300  # 5 minutes
    end

    # Add virtual IP that we should respond to
    def add_virtual_ip(ip_address, mac_address)
      @virtual_ips[ip_address] = {
        mac: mac_address,
        added_at: Time.now
      }
    end

    # Remove virtual IP
    def remove_virtual_ip(ip_address)
      @virtual_ips.delete(ip_address)
    end

    # Process incoming ARP packet
    def process_packet(arp_packet, interface)
      case arp_packet.operation
      when ArpPacket::OP_REQUEST
        process_arp_request(arp_packet, interface)
      when ArpPacket::OP_REPLY  
        process_arp_reply(arp_packet)
      end
    end

    # Process ARP request - reply if for our virtual IP
    def process_arp_request(request, interface)
      target_ip = request.target_ip_string
      
      # Check if request is for one of our virtual IPs
      virtual_ip_info = @virtual_ips[target_ip]
      return nil unless virtual_ip_info

      # Create ARP reply
      reply = ArpPacket.create_reply(
        sender_mac: virtual_ip_info[:mac],
        sender_ip: target_ip,
        target_mac: request.sender_mac_string,
        target_ip: request.sender_ip_string
      )

      # Create Ethernet frame for reply
      eth_frame = EthernetFrame.create(
        destination_mac: request.sender_mac_string,
        source_mac: virtual_ip_info[:mac],
        ethertype: EthernetFrame::ETHERTYPE_ARP,
        payload: reply.to_binary_s
      )

      # Update our ARP cache with requester info
      update_arp_cache(request.sender_ip_string, request.sender_mac_string)

      eth_frame.to_binary_s
    end

    # Process ARP reply - update cache
    def process_arp_reply(reply)
      update_arp_cache(reply.sender_ip_string, reply.sender_mac_string)
      nil
    end

    # Update ARP cache with IP->MAC mapping
    def update_arp_cache(ip_address, mac_address)
      @arp_cache[ip_address] = {
        mac: mac_address,
        updated_at: Time.now
      }
      
      # Clean old entries periodically
      clean_arp_cache if @arp_cache.size > 1000
    end

    # Lookup MAC address for IP
    def lookup_mac(ip_address)
      entry = @arp_cache[ip_address]
      return nil unless entry
      
      # Check if entry is still valid
      if Time.now - entry[:updated_at] > @arp_cache_timeout
        @arp_cache.delete(ip_address)
        return nil
      end
      
      entry[:mac]
    end

    # Create ARP request for IP resolution
    def create_request(target_ip, sender_mac, sender_ip)
      arp_packet = ArpPacket.create_request(
        sender_mac: sender_mac,
        sender_ip: sender_ip,
        target_ip: target_ip
      )

      # Broadcast ARP request
      EthernetFrame.create(
        destination_mac: "ff:ff:ff:ff:ff:ff",
        source_mac: sender_mac,
        ethertype: EthernetFrame::ETHERTYPE_ARP,
        payload: arp_packet.to_binary_s
      ).to_binary_s
    end

    # Get ARP cache statistics
    def cache_stats
      {
        entries: @arp_cache.size,
        virtual_ips: @virtual_ips.size,
        oldest_entry: @arp_cache.values.map { |e| e[:updated_at] }.min,
        newest_entry: @arp_cache.values.map { |e| e[:updated_at] }.max
      }
    end

    private

    # Clean expired entries from ARP cache
    def clean_arp_cache
      now = Time.now
      @arp_cache.delete_if { |_, entry| now - entry[:updated_at] > @arp_cache_timeout }
    end
  end
end
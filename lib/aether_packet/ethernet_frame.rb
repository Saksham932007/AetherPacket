# frozen_string_literal: true

require "bindata"

module AetherPacket
  # EthernetFrame parses Layer 2 Ethernet frames with VLAN support
  # Implements IEEE 802.3 and 802.1Q specifications
  class EthernetFrame < BinData::Record
    # Ethernet header constants
    ETHERTYPE_IPv4 = 0x0800
    ETHERTYPE_IPv6 = 0x86dd  
    ETHERTYPE_ARP = 0x0806
    ETHERTYPE_VLAN = 0x8100  # 802.1Q VLAN tag
    ETHERTYPE_QINQ = 0x88a8  # 802.1ad QinQ

    # Minimum Ethernet frame size (without FCS)
    MIN_FRAME_SIZE = 64
    MAX_FRAME_SIZE = 1518  # Without VLAN tags

    # MAC address parsing
    array :destination_mac, type: :uint8, initial_length: 6
    array :source_mac, type: :uint8, initial_length: 6
    
    # EtherType/Length field
    uint16be :ethertype_length
    
    # Optional VLAN tag (802.1Q)
    struct :vlan_tag, onlyif: -> { ethertype_length == ETHERTYPE_VLAN } do
      bit4 :priority         # Priority Code Point (PCP)
      bit1 :drop_eligible    # Drop Eligible Indicator (DEI) 
      bit11 :vlan_id         # VLAN Identifier
      uint16be :ethertype    # Actual EtherType after VLAN
    end
    
    # Payload data (rest of frame)
    rest :payload

    # Parse raw Ethernet frame data
    def self.parse(raw_data)
      begin
        frame = new
        frame.read(raw_data)
        frame.validate!
        frame
      rescue BinData::ValidityError => e
        raise MalformedPacketError, "Invalid Ethernet frame: #{e.message}"
      end
    end

    # Validate frame integrity
    def validate!
      raise MalformedPacketError, "Frame too small" if total_length < MIN_FRAME_SIZE
      raise MalformedPacketError, "Invalid MAC address" unless valid_mac_addresses?
      raise MalformedPacketError, "Invalid EtherType" unless valid_ethertype?
    end

    # Get destination MAC as formatted string
    def destination_mac_string
      destination_mac.map { |byte| format("%02x", byte) }.join(":")
    end

    # Get source MAC as formatted string  
    def source_mac_string
      source_mac.map { |byte| format("%02x", byte) }.join(":")
    end

    # Check if frame has VLAN tag
    def vlan_tagged?
      ethertype_length == ETHERTYPE_VLAN
    end

    # Get actual EtherType (accounting for VLAN)
    def actual_ethertype
      vlan_tagged? ? vlan_tag.ethertype : ethertype_length
    end

    # Get VLAN ID (0 if not tagged)
    def vlan_id
      vlan_tagged? ? vlan_tag.vlan_id : 0
    end

    # Get VLAN priority (0 if not tagged)
    def vlan_priority
      vlan_tagged? ? vlan_tag.priority : 0
    end

    # Check if destination is broadcast
    def broadcast?
      destination_mac.all? { |byte| byte == 0xff }
    end

    # Check if destination is multicast
    def multicast?
      !broadcast? && (destination_mac[0] & 0x01) == 0x01
    end

    # Check if destination is unicast
    def unicast?
      !multicast?
    end

    # Get frame type as symbol
    def frame_type
      case actual_ethertype
      when ETHERTYPE_IPv4 then :ipv4
      when ETHERTYPE_IPv6 then :ipv6
      when ETHERTYPE_ARP then :arp
      when 0x0..0x05dc then :ieee_802_3  # Length field
      else :unknown
      end
    end

    # Get payload size
    def payload_size
      payload.bytesize
    end

    # Get total frame size
    def total_length
      num_bytes
    end

    # Extract frame metadata for analysis
    def metadata
      {
        destination_mac: destination_mac_string,
        source_mac: source_mac_string,
        ethertype: actual_ethertype,
        frame_type: frame_type,
        vlan_tagged: vlan_tagged?,
        vlan_id: vlan_id,
        vlan_priority: vlan_priority,
        broadcast: broadcast?,
        multicast: multicast?,
        payload_size: payload_size,
        total_size: total_length
      }
    end

    # Create new Ethernet frame
    def self.create(destination_mac:, source_mac:, ethertype:, payload:, vlan_id: nil, vlan_priority: 0)
      frame = new
      
      # Set MAC addresses
      frame.destination_mac = parse_mac_address(destination_mac)
      frame.source_mac = parse_mac_address(source_mac)
      
      # Handle VLAN tagging
      if vlan_id
        frame.ethertype_length = ETHERTYPE_VLAN
        frame.vlan_tag.priority = vlan_priority
        frame.vlan_tag.drop_eligible = 0
        frame.vlan_tag.vlan_id = vlan_id
        frame.vlan_tag.ethertype = ethertype
      else
        frame.ethertype_length = ethertype
      end
      
      frame.payload = payload
      frame
    end

    private

    def valid_mac_addresses?
      destination_mac.length == 6 && source_mac.length == 6
    end

    def valid_ethertype?
      # EtherType should be > 1500 (0x05dc) or valid length
      ethertype_length > 0x05dc || ethertype_length <= payload_size
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
end
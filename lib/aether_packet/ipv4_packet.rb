# frozen_string_literal: true

require "bindata"

module AetherPacket
  # IPv4Packet parses and validates IPv4 headers per RFC 791
  # Implements checksum validation and options parsing
  class IPv4Packet < BinData::Record
    # IP Protocol numbers
    PROTO_ICMP = 1
    PROTO_TCP = 6
    PROTO_UDP = 17
    
    # IP Flags
    FLAG_RESERVED = 0x4
    FLAG_DONT_FRAGMENT = 0x2
    FLAG_MORE_FRAGMENTS = 0x1
    
    # Header fields
    bit4 :version              # IP version (4)
    bit4 :header_length        # Header length in 32-bit words
    uint8 :type_of_service     # Type of Service (DSCP + ECN)
    uint16be :total_length     # Total packet length
    uint16be :identification   # Fragment identification
    bit3 :flags               # Control flags
    bit13 :fragment_offset    # Fragment offset in 8-byte units
    uint8 :ttl                # Time to Live
    uint8 :protocol           # Next protocol
    uint16be :header_checksum # Header checksum
    uint32be :source_ip       # Source IP address
    uint32be :destination_ip  # Destination IP address
    
    # Variable-length options field
    string :options, read_length: -> { (header_length - 5) * 4 }
    
    # Payload data
    rest :payload

    # Parse raw IPv4 packet data
    def self.parse(raw_data)
      begin
        packet = new
        packet.read(raw_data)
        packet.validate!
        packet
      rescue BinData::ValidityError => e
        raise MalformedPacketError, "Invalid IPv4 packet: #{e.message}"
      end
    end

    # Validate packet integrity
    def validate!
      raise MalformedPacketError, "Invalid IP version" unless version == 4
      raise MalformedPacketError, "Invalid header length" unless header_length >= 5
      raise MalformedPacketError, "Packet too small" unless total_length >= header_size
      raise MalformedPacketError, "Invalid total length" unless total_length <= num_bytes
      
      validate_checksum!
    end

    # Get source IP as dotted decimal string
    def source_ip_string
      ip_to_string(source_ip)
    end

    # Get destination IP as dotted decimal string  
    def destination_ip_string
      ip_to_string(destination_ip)
    end

    # Get header size in bytes
    def header_size
      header_length * 4
    end

    # Get payload size in bytes
    def payload_size
      total_length - header_size
    end

    # Check if packet is fragmented
    def fragmented?
      (flags & FLAG_MORE_FRAGMENTS) != 0 || fragment_offset != 0
    end

    # Check if Don't Fragment flag is set
    def dont_fragment?
      (flags & FLAG_DONT_FRAGMENT) != 0
    end

    # Get protocol as symbol
    def protocol_name
      case protocol
      when PROTO_ICMP then :icmp
      when PROTO_TCP then :tcp
      when PROTO_UDP then :udp
      else :unknown
      end
    end

    # Calculate IPv4 header checksum
    def calculate_checksum
      # Zero out checksum field for calculation
      header_data = to_binary_s[0, header_size]
      header_bytes = header_data.unpack("n*")
      
      # Set checksum field to 0
      header_bytes[5] = 0
      
      # Calculate one's complement sum
      sum = header_bytes.sum
      
      # Add carry bits
      while (sum >> 16) > 0
        sum = (sum & 0xffff) + (sum >> 16)
      end
      
      # One's complement
      ~sum & 0xffff
    end

    # Validate header checksum
    def validate_checksum!
      calculated = calculate_checksum
      raise ChecksumError, "Invalid IPv4 checksum: expected #{calculated.to_s(16)}, got #{header_checksum.to_s(16)}" unless calculated == header_checksum
    end

    # Update checksum field
    def update_checksum!
      self.header_checksum = 0
      self.header_checksum = calculate_checksum
    end

    # Decrement TTL for forwarding
    def decrement_ttl!
      raise NetworkError, "TTL expired" if ttl <= 1
      self.ttl -= 1
      update_checksum!
    end

    # Parse IPv4 options
    def parse_options
      return [] if options.empty?
      
      opts = []
      offset = 0
      
      while offset < options.bytesize
        option_type = options.getbyte(offset)
        
        # End of Options List
        break if option_type == 0
        
        # No Operation
        if option_type == 1
          opts << { type: :nop }
          offset += 1
          next
        end
        
        # Variable length option
        break if offset + 1 >= options.bytesize
        option_length = options.getbyte(offset + 1)
        break if option_length < 2 || offset + option_length > options.bytesize
        
        option_data = options[offset + 2, option_length - 2]
        opts << {
          type: option_type,
          length: option_length,
          data: option_data
        }
        
        offset += option_length
      end
      
      opts
    end

    # Extract packet metadata
    def metadata
      {
        version: version,
        header_length: header_length,
        type_of_service: type_of_service,
        total_length: total_length,
        identification: identification,
        flags: flags,
        fragment_offset: fragment_offset,
        ttl: ttl,
        protocol: protocol,
        protocol_name: protocol_name,
        source_ip: source_ip_string,
        destination_ip: destination_ip_string,
        fragmented: fragmented?,
        dont_fragment: dont_fragment?,
        header_size: header_size,
        payload_size: payload_size,
        options: parse_options
      }
    end

    # Create new IPv4 packet
    def self.create(source_ip:, destination_ip:, protocol:, payload:, ttl: 64, identification: nil)
      packet = new
      
      packet.version = 4
      packet.header_length = 5  # No options
      packet.type_of_service = 0
      packet.total_length = 20 + payload.bytesize
      packet.identification = identification || rand(0xffff)
      packet.flags = FLAG_DONT_FRAGMENT
      packet.fragment_offset = 0
      packet.ttl = ttl
      packet.protocol = protocol
      packet.source_ip = string_to_ip(source_ip)
      packet.destination_ip = string_to_ip(destination_ip)
      packet.options = ""
      packet.payload = payload
      
      packet.update_checksum!
      packet
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
  end
end
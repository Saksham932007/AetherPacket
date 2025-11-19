# frozen_string_literal: true

require "bindata"

module AetherPacket
  # UdpDatagram parses UDP headers per RFC 768
  # Implements checksum validation and payload extraction
  class UdpDatagram < BinData::Record
    # UDP header is exactly 8 bytes
    UDP_HEADER_SIZE = 8
    
    # Well-known UDP ports
    PORT_DNS = 53
    PORT_DHCP_SERVER = 67
    PORT_DHCP_CLIENT = 68
    PORT_TFTP = 69
    PORT_NTP = 123
    PORT_SNMP = 161
    PORT_SYSLOG = 514

    uint16be :source_port      # Source port number
    uint16be :destination_port # Destination port number
    uint16be :length          # UDP header + data length
    uint16be :checksum        # UDP checksum (optional in IPv4)
    rest :payload             # UDP payload data

    # Parse raw UDP datagram data
    def self.parse(raw_data)
      begin
        datagram = new
        datagram.read(raw_data)
        datagram.validate!
        datagram
      rescue BinData::ValidityError => e
        raise MalformedPacketError, "Invalid UDP datagram: #{e.message}"
      end
    end

    # Validate UDP datagram
    def validate!
      raise MalformedPacketError, "UDP datagram too small" if num_bytes < UDP_HEADER_SIZE
      raise MalformedPacketError, "Invalid length field" unless length >= UDP_HEADER_SIZE
      raise MalformedPacketError, "Length mismatch" unless length == num_bytes
      
      # Note: UDP checksum validation requires pseudo-header from IP layer
      # This is handled by the validate_checksum_with_pseudo_header method
    end

    # Get payload size
    def payload_size
      length - UDP_HEADER_SIZE
    end

    # Check if this is a DNS packet
    def dns_packet?
      source_port == PORT_DNS || destination_port == PORT_DNS
    end

    # Check if this is a DHCP packet
    def dhcp_packet?
      (source_port == PORT_DHCP_SERVER && destination_port == PORT_DHCP_CLIENT) ||
      (source_port == PORT_DHCP_CLIENT && destination_port == PORT_DHCP_SERVER)
    end

    # Get service name for well-known ports
    def service_name
      port = destination_port
      case port
      when PORT_DNS then :dns
      when PORT_DHCP_SERVER, PORT_DHCP_CLIENT then :dhcp
      when PORT_TFTP then :tftp
      when PORT_NTP then :ntp
      when PORT_SNMP then :snmp
      when PORT_SYSLOG then :syslog
      when 80 then :http
      when 443 then :https
      when 25 then :smtp
      when 110 then :pop3
      when 143 then :imap
      when 993 then :imaps
      when 995 then :pop3s
      else :unknown
      end
    end

    # Calculate UDP checksum with pseudo-header
    def calculate_checksum(source_ip, destination_ip)
      # Create pseudo-header for checksum calculation
      # Pseudo-header: source IP (4) + dest IP (4) + zero (1) + protocol (1) + UDP length (2)
      pseudo_header = [
        source_ip,           # Source IP (32-bit)
        destination_ip,      # Destination IP (32-bit)
        IPv4Packet::PROTO_UDP,  # Protocol (8-bit, with zero padding)
        length               # UDP length (16-bit)
      ].pack("NNnN")[0, 12]  # Take only 12 bytes
      
      # Combine pseudo-header with UDP header and data
      udp_data = to_binary_s
      udp_bytes = udp_data.unpack("C*")
      
      # Zero out checksum field (bytes 6-7)
      udp_bytes[6] = 0
      udp_bytes[7] = 0
      
      # Combine pseudo-header and UDP data
      checksum_data = pseudo_header + udp_bytes.pack("C*")
      
      # Pad to even length if necessary
      checksum_data += "\x00" if checksum_data.length.odd?
      
      # Calculate checksum over 16-bit words
      sum = checksum_data.unpack("n*").sum
      
      # Add carry bits
      while (sum >> 16) > 0
        sum = (sum & 0xffff) + (sum >> 16)
      end
      
      # Return one's complement (0 means checksum is disabled)
      result = ~sum & 0xffff
      result == 0 ? 0xffff : result
    end

    # Validate UDP checksum with IP addresses
    def validate_checksum_with_pseudo_header(source_ip, destination_ip)
      # UDP checksum is optional in IPv4 - zero means no checksum
      return true if checksum == 0
      
      calculated = calculate_checksum(source_ip, destination_ip)
      raise ChecksumError, "Invalid UDP checksum: expected #{calculated.to_s(16)}, got #{checksum.to_s(16)}" unless calculated == checksum
      true
    end

    # Update checksum field with proper pseudo-header
    def update_checksum!(source_ip, destination_ip)
      self.checksum = 0
      self.checksum = calculate_checksum(source_ip, destination_ip)
    end

    # Create UDP datagram
    def self.create(source_port:, destination_port:, payload:)
      datagram = new
      datagram.source_port = source_port
      datagram.destination_port = destination_port
      datagram.length = UDP_HEADER_SIZE + payload.bytesize
      datagram.checksum = 0  # Will be calculated later with IP addresses
      datagram.payload = payload
      datagram
    end

    # Extract connection tuple for tracking
    def connection_tuple(source_ip, destination_ip)
      {
        protocol: :udp,
        source_ip: source_ip,
        source_port: source_port,
        destination_ip: destination_ip,
        destination_port: destination_port
      }
    end

    # Get reverse connection tuple (for return traffic)
    def reverse_connection_tuple(source_ip, destination_ip)
      {
        protocol: :udp,
        source_ip: destination_ip,
        source_port: destination_port,
        destination_ip: source_ip,
        destination_port: source_port
      }
    end

    # Check if this is likely a client->server connection
    def client_to_server?
      # Heuristics: client usually uses ephemeral port (>1024)
      source_port > 1024 && destination_port <= 1024
    end

    # Check if this is likely a server->client response
    def server_to_client?
      # Heuristics: server usually uses well-known port (<1024)
      source_port <= 1024 && destination_port > 1024
    end

    # Extract packet metadata
    def metadata
      {
        source_port: source_port,
        destination_port: destination_port,
        length: length,
        payload_size: payload_size,
        checksum: checksum,
        service: service_name,
        is_dns: dns_packet?,
        is_dhcp: dhcp_packet?,
        direction: client_to_server? ? :client_to_server : :server_to_client
      }
    end

    # Get flow identifier for connection tracking
    def flow_id(source_ip, destination_ip)
      # Create consistent flow identifier regardless of direction
      if source_ip < destination_ip || (source_ip == destination_ip && source_port < destination_port)
        "#{source_ip}:#{source_port}-#{destination_ip}:#{destination_port}/udp"
      else
        "#{destination_ip}:#{destination_port}-#{source_ip}:#{source_port}/udp"
      end
    end

    # Check if packet matches flow (either direction)
    def matches_flow?(flow_tuple)
      (flow_tuple[:source_ip] == metadata[:source_ip] && 
       flow_tuple[:source_port] == source_port &&
       flow_tuple[:destination_ip] == metadata[:destination_ip] &&
       flow_tuple[:destination_port] == destination_port) ||
      (flow_tuple[:source_ip] == metadata[:destination_ip] && 
       flow_tuple[:source_port] == destination_port &&
       flow_tuple[:destination_ip] == metadata[:source_ip] &&
       flow_tuple[:destination_port] == source_port)
    end

    # Extract application data for DPI
    def application_data
      payload
    end

    # Get packet size including headers
    def total_size
      num_bytes
    end
  end
end
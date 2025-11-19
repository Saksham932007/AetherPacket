# frozen_string_literal: true

require "bindata"

module AetherPacket
  # TcpSegment parses TCP segments per RFC 793
  # Implements sequence/acknowledgment tracking and flag processing
  class TcpSegment < BinData::Record
    # Minimum TCP header size (without options)
    TCP_MIN_HEADER_SIZE = 20
    
    # TCP Flags
    FLAG_FIN = 0x01   # Finish - no more data
    FLAG_SYN = 0x02   # Synchronize sequence numbers  
    FLAG_RST = 0x04   # Reset connection
    FLAG_PSH = 0x08   # Push - deliver data immediately
    FLAG_ACK = 0x10   # Acknowledgment field significant
    FLAG_URG = 0x20   # Urgent pointer field significant
    FLAG_ECE = 0x40   # ECN Echo
    FLAG_CWR = 0x80   # Congestion Window Reduced

    # Well-known TCP ports
    PORT_HTTP = 80
    PORT_HTTPS = 443
    PORT_SMTP = 25
    PORT_POP3 = 110
    PORT_IMAP = 143
    PORT_SSH = 22
    PORT_TELNET = 23
    PORT_FTP_CONTROL = 21
    PORT_FTP_DATA = 20

    uint16be :source_port      # Source port number
    uint16be :destination_port # Destination port number
    uint32be :sequence_number  # Sequence number
    uint32be :acknowledgment_number # Acknowledgment number
    bit4 :data_offset         # Header length in 32-bit words
    bit6 :reserved            # Reserved bits (should be zero)
    bit6 :flags              # Control flags
    uint16be :window_size     # Window size
    uint16be :checksum        # TCP checksum
    uint16be :urgent_pointer  # Urgent pointer
    
    # Variable-length options field
    string :options, read_length: -> { (data_offset - 5) * 4 }
    
    # TCP payload data
    rest :payload

    # Parse raw TCP segment data
    def self.parse(raw_data)
      begin
        segment = new
        segment.read(raw_data)
        segment.validate!
        segment
      rescue BinData::ValidityError => e
        raise MalformedPacketError, "Invalid TCP segment: #{e.message}"
      end
    end

    # Validate TCP segment
    def validate!
      raise MalformedPacketError, "TCP segment too small" if num_bytes < TCP_MIN_HEADER_SIZE
      raise MalformedPacketError, "Invalid data offset" unless data_offset >= 5 && data_offset <= 15
      raise MalformedPacketError, "Header size mismatch" unless header_size <= num_bytes
      
      # Validate flag combinations
      validate_flag_combinations!
    end

    # Get header size in bytes
    def header_size
      data_offset * 4
    end

    # Get payload size
    def payload_size
      num_bytes - header_size
    end

    # Flag checking methods
    def fin?
      (flags & FLAG_FIN) != 0
    end

    def syn?
      (flags & FLAG_SYN) != 0
    end

    def rst?
      (flags & FLAG_RST) != 0
    end

    def psh?
      (flags & FLAG_PSH) != 0
    end

    def ack?
      (flags & FLAG_ACK) != 0
    end

    def urg?
      (flags & FLAG_URG) != 0
    end

    def ece?
      (flags & FLAG_ECE) != 0
    end

    def cwr?
      (flags & FLAG_CWR) != 0
    end

    # Get flag names as array
    def flag_names
      names = []
      names << :fin if fin?
      names << :syn if syn?
      names << :rst if rst?
      names << :psh if psh?
      names << :ack if ack?
      names << :urg if urg?
      names << :ece if ece?
      names << :cwr if cwr?
      names
    end

    # Connection establishment flags
    def connection_request?
      syn? && !ack?
    end

    def connection_response?
      syn? && ack?
    end

    def connection_ack?
      ack? && !syn? && payload_size == 0
    end

    # Connection termination flags
    def connection_close?
      fin?
    end

    def connection_reset?
      rst?
    end

    # Get service name for well-known ports
    def service_name
      port = destination_port
      case port
      when PORT_HTTP then :http
      when PORT_HTTPS then :https
      when PORT_SMTP then :smtp
      when PORT_POP3 then :pop3
      when PORT_IMAP then :imap
      when PORT_SSH then :ssh
      when PORT_TELNET then :telnet
      when PORT_FTP_CONTROL then :ftp_control
      when PORT_FTP_DATA then :ftp_data
      when 3306 then :mysql
      when 5432 then :postgresql
      when 6379 then :redis
      when 27017 then :mongodb
      else :unknown
      end
    end

    # Calculate TCP checksum with pseudo-header
    def calculate_checksum(source_ip, destination_ip)
      # Create pseudo-header for checksum calculation
      pseudo_header = [
        source_ip,           # Source IP (32-bit)
        destination_ip,      # Destination IP (32-bit)
        IPv4Packet::PROTO_TCP,  # Protocol (8-bit, with zero padding)
        num_bytes           # TCP length (16-bit)
      ].pack("NNnN")[0, 12]  # Take only 12 bytes
      
      # Combine pseudo-header with TCP header and data
      tcp_data = to_binary_s
      tcp_bytes = tcp_data.unpack("C*")
      
      # Zero out checksum field (bytes 16-17)
      tcp_bytes[16] = 0
      tcp_bytes[17] = 0
      
      # Combine pseudo-header and TCP data
      checksum_data = pseudo_header + tcp_bytes.pack("C*")
      
      # Pad to even length if necessary
      checksum_data += "\x00" if checksum_data.length.odd?
      
      # Calculate checksum over 16-bit words
      sum = checksum_data.unpack("n*").sum
      
      # Add carry bits
      while (sum >> 16) > 0
        sum = (sum & 0xffff) + (sum >> 16)
      end
      
      # Return one's complement
      ~sum & 0xffff
    end

    # Validate TCP checksum with IP addresses
    def validate_checksum_with_pseudo_header(source_ip, destination_ip)
      calculated = calculate_checksum(source_ip, destination_ip)
      raise ChecksumError, "Invalid TCP checksum: expected #{calculated.to_s(16)}, got #{checksum.to_s(16)}" unless calculated == checksum
      true
    end

    # Update checksum field
    def update_checksum!(source_ip, destination_ip)
      self.checksum = 0
      self.checksum = calculate_checksum(source_ip, destination_ip)
    end

    # Parse TCP options
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
        
        case option_type
        when 2  # Maximum Segment Size
          opts << { type: :mss, value: option_data.unpack("n")[0] }
        when 3  # Window Scale
          opts << { type: :window_scale, value: option_data.unpack("C")[0] }
        when 4  # SACK Permitted
          opts << { type: :sack_permitted }
        when 5  # SACK
          opts << { type: :sack, data: option_data }
        when 8  # Timestamp
          opts << { type: :timestamp, data: option_data.unpack("NN") }
        else
          opts << { type: option_type, length: option_length, data: option_data }
        end
        
        offset += option_length
      end
      
      opts
    end

    # Create TCP segment
    def self.create(source_port:, destination_port:, sequence:, acknowledgment: 0, 
                   flags: 0, window: 65535, payload: "")
      segment = new
      segment.source_port = source_port
      segment.destination_port = destination_port
      segment.sequence_number = sequence
      segment.acknowledgment_number = acknowledgment
      segment.data_offset = 5  # No options
      segment.reserved = 0
      segment.flags = flags
      segment.window_size = window
      segment.checksum = 0  # Will be calculated later
      segment.urgent_pointer = 0
      segment.options = ""
      segment.payload = payload
      segment
    end

    # Extract connection tuple for tracking
    def connection_tuple(source_ip, destination_ip)
      {
        protocol: :tcp,
        source_ip: source_ip,
        source_port: source_port,
        destination_ip: destination_ip,
        destination_port: destination_port
      }
    end

    # Get reverse connection tuple
    def reverse_connection_tuple(source_ip, destination_ip)
      {
        protocol: :tcp,
        source_ip: destination_ip,
        source_port: destination_port,
        destination_ip: source_ip,
        destination_port: source_port
      }
    end

    # Extract sequence space information
    def sequence_info
      {
        sequence_number: sequence_number,
        acknowledgment_number: acknowledgment_number,
        sequence_end: sequence_number + payload_size + (syn? ? 1 : 0) + (fin? ? 1 : 0),
        window_size: window_size,
        payload_size: payload_size
      }
    end

    # Extract packet metadata
    def metadata
      {
        source_port: source_port,
        destination_port: destination_port,
        sequence_number: sequence_number,
        acknowledgment_number: acknowledgment_number,
        flags: flag_names,
        window_size: window_size,
        payload_size: payload_size,
        header_size: header_size,
        service: service_name,
        connection_state: infer_connection_state,
        options: parse_options
      }
    end

    # Infer connection state from flags
    def infer_connection_state
      return :syn_sent if syn? && !ack?
      return :syn_received if syn? && ack?
      return :established if ack? && !syn? && !fin? && !rst?
      return :fin_wait if fin? && !rst?
      return :reset if rst?
      return :closed if !syn? && !ack? && !fin? && !rst?
      :unknown
    end

    # Get flow identifier
    def flow_id(source_ip, destination_ip)
      # Create consistent flow identifier
      if source_ip < destination_ip || (source_ip == destination_ip && source_port < destination_port)
        "#{source_ip}:#{source_port}-#{destination_ip}:#{destination_port}/tcp"
      else
        "#{destination_ip}:#{destination_port}-#{source_ip}:#{source_port}/tcp"
      end
    end

    # Extract application data for DPI
    def application_data
      payload
    end

    private

    # Validate TCP flag combinations
    def validate_flag_combinations!
      # SYN and FIN should not be set together
      raise MalformedPacketError, "Invalid flag combination: SYN+FIN" if syn? && fin?
      
      # RST should not be combined with SYN (except in some attack scenarios)
      # This is a warning rather than an error for security analysis
      
      # ACK should be set for most packets except initial SYN
      # This is also more of a heuristic than a strict rule
    end
  end
end
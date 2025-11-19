# frozen_string_literal: true

require 'bindata'

module AetherPacket
  # DNS Header structure for DNS packet parsing
  class DnsHeader < BinData::Record
    endian :big
    
    uint16 :transaction_id
    bit1   :qr_flag           # Query/Response flag
    bit4   :opcode           # Operation code
    bit1   :aa_flag          # Authoritative Answer flag
    bit1   :tc_flag          # Truncation flag
    bit1   :rd_flag          # Recursion Desired flag
    bit1   :ra_flag          # Recursion Available flag
    bit3   :reserved         # Reserved bits (must be zero)
    bit4   :rcode            # Response code
    uint16 :question_count
    uint16 :answer_count
    uint16 :authority_count
    uint16 :additional_count

    def query?
      qr_flag == 0
    end

    def response?
      qr_flag == 1
    end

    def response_code_name
      case rcode
      when 0 then :no_error
      when 1 then :format_error
      when 2 then :server_failure
      when 3 then :name_error
      when 4 then :not_implemented
      when 5 then :refused
      else :unknown
      end
    end

    def opcode_name
      case opcode
      when 0 then :query
      when 1 then :inverse_query
      when 2 then :status
      else :unknown
      end
    end
  end

  # DNS Question section
  class DnsQuestion < BinData::Record
    string :name, read_length: -> { read_dns_name.bytesize }
    uint16 :qtype
    uint16 :qclass

    def qtype_name
      case qtype
      when 1 then :A
      when 2 then :NS
      when 5 then :CNAME
      when 6 then :SOA
      when 12 then :PTR
      when 15 then :MX
      when 16 then :TXT
      when 28 then :AAAA
      when 33 then :SRV
      else :unknown
      end
    end

    def qclass_name
      case qclass
      when 1 then :IN
      when 2 then :CS
      when 3 then :CH
      when 4 then :HS
      else :unknown
      end
    end

    private

    def read_dns_name
      # Simplified DNS name reading - would need full label compression support
      name_data = ""
      pos = 0
      
      loop do
        length = eval_parameter(:parent).snapshot[pos]
        break if length == 0
        
        pos += 1
        name_data += eval_parameter(:parent).snapshot[pos, length]
        name_data += "." unless pos + length >= eval_parameter(:parent).snapshot.length
        pos += length
      end
      
      name_data
    end
  end

  # DNS Resource Record
  class DnsResourceRecord < BinData::Record
    string :name, read_length: -> { read_dns_name.bytesize }
    uint16 :rtype
    uint16 :rclass
    uint32 :ttl
    uint16 :data_length
    string :rdata, read_length: :data_length

    def rtype_name
      case rtype
      when 1 then :A
      when 2 then :NS
      when 5 then :CNAME
      when 6 then :SOA
      when 12 then :PTR
      when 15 then :MX
      when 16 then :TXT
      when 28 then :AAAA
      else :unknown
      end
    end

    def parsed_rdata
      case rtype
      when 1  # A record
        rdata.unpack('C4').join('.')
      when 28 # AAAA record
        rdata.unpack('n8').map { |x| x.to_s(16) }.join(':')
      when 2, 5, 12  # NS, CNAME, PTR
        parse_domain_name(rdata)
      when 15 # MX record
        priority = rdata[0..1].unpack1('n')
        exchange = parse_domain_name(rdata[2..-1])
        { priority: priority, exchange: exchange }
      else
        rdata.unpack1('H*')  # Hex representation for unknown types
      end
    end

    private

    def read_dns_name
      # Simplified implementation
      ""
    end

    def parse_domain_name(data)
      # Simplified domain name parsing
      data.unpack1('H*')
    end
  end

  # DNS Packet parser and manipulator
  class DnsPacket
    attr_reader :header, :questions, :answers, :authorities, :additionals, :raw_data

    def initialize(data = nil)
      @questions = []
      @answers = []
      @authorities = []
      @additionals = []
      
      if data
        @raw_data = data
        parse_packet(data)
      else
        @header = create_default_header
      end
    end

    # Parse DNS packet from binary data
    def parse_packet(data)
      return false if data.bytesize < 12  # Minimum DNS header size
      
      begin
        @header = DnsHeader.read(data)
        offset = 12  # DNS header is 12 bytes
        
        # Parse questions
        @header.question_count.times do
          question, offset = parse_question(data, offset)
          @questions << question if question
        end
        
        # Parse answers
        @header.answer_count.times do
          answer, offset = parse_resource_record(data, offset)
          @answers << answer if answer
        end
        
        # Parse authority records
        @header.authority_count.times do
          authority, offset = parse_resource_record(data, offset)
          @authorities << authority if authority
        end
        
        # Parse additional records
        @header.additional_count.times do
          additional, offset = parse_resource_record(data, offset)
          @additionals << additional if additional
        end
        
        true
      rescue BinData::ValidityError, ArgumentError => e
        puts "DNS parsing error: #{e.message}"
        false
      end
    end

    # Check if packet is a DNS query
    def query?
      @header&.query?
    end

    # Check if packet is a DNS response
    def response?
      @header&.response?
    end

    # Get primary queried domain
    def queried_domain
      return nil if @questions.empty?
      @questions.first[:name]
    end

    # Get all queried domains
    def all_queried_domains
      @questions.map { |q| q[:name] }.compact
    end

    # Extract IP addresses from A/AAAA records
    def resolved_ips
      ips = []
      
      @answers.each do |answer|
        case answer[:rtype]
        when 1  # A record
          ips << answer[:rdata].unpack('C4').join('.')
        when 28 # AAAA record
          ips << answer[:rdata].unpack('n8').map { |x| x.to_s(16) }.join(':')
        end
      end
      
      ips
    end

    # Check for suspicious DNS characteristics
    def suspicious_characteristics
      suspicious = []
      
      # Check for excessive subdomains
      all_queried_domains.each do |domain|
        next unless domain
        subdomain_count = domain.count('.')
        suspicious << :excessive_subdomains if subdomain_count > 10
      end
      
      # Check for DGA (Domain Generation Algorithm) patterns
      all_queried_domains.each do |domain|
        next unless domain
        # Simple heuristic: long domains with high entropy
        if domain.length > 30 && calculate_entropy(domain) > 3.5
          suspicious << :possible_dga
        end
      end
      
      # Check for DNS tunneling indicators
      if query? && @questions.any? { |q| q[:qtype] == 16 }  # TXT records
        suspicious << :possible_dns_tunneling
      end
      
      # Check for response size anomalies
      if response? && @raw_data&.bytesize && @raw_data.bytesize > 1024
        suspicious << :large_response
      end
      
      suspicious.uniq
    end

    # Get packet statistics
    def packet_stats
      {
        transaction_id: @header&.transaction_id,
        is_query: query?,
        is_response: response?,
        opcode: @header&.opcode_name,
        response_code: @header&.response_code_name,
        question_count: @questions.size,
        answer_count: @answers.size,
        authority_count: @authorities.size,
        additional_count: @additionals.size,
        packet_size: @raw_data&.bytesize || 0,
        queried_domains: all_queried_domains,
        resolved_ips: resolved_ips,
        suspicious_characteristics: suspicious_characteristics
      }
    end

    # Convert to binary representation
    def to_binary_s
      return @raw_data if @raw_data
      
      # Would need full DNS packet construction implementation
      # This is a simplified placeholder
      packet_data = ""
      packet_data += @header.to_binary_s if @header
      packet_data
    end

    private

    def create_default_header
      DnsHeader.new.tap do |header|
        header.transaction_id = rand(65536)
        header.qr_flag = 0
        header.opcode = 0
        header.rd_flag = 1
        header.question_count = 0
        header.answer_count = 0
        header.authority_count = 0
        header.additional_count = 0
      end
    end

    def parse_question(data, offset)
      return [nil, offset] if offset >= data.bytesize
      
      begin
        # Parse domain name
        name, new_offset = parse_domain_name(data, offset)
        return [nil, offset] if new_offset + 4 > data.bytesize
        
        # Parse QTYPE and QCLASS
        qtype = data[new_offset, 2].unpack1('n')
        qclass = data[new_offset + 2, 2].unpack1('n')
        
        question = {
          name: name,
          qtype: qtype,
          qclass: qclass,
          qtype_name: qtype_to_name(qtype),
          qclass_name: qclass_to_name(qclass)
        }
        
        [question, new_offset + 4]
      rescue => e
        puts "Question parsing error: #{e.message}"
        [nil, offset]
      end
    end

    def parse_resource_record(data, offset)
      return [nil, offset] if offset >= data.bytesize
      
      begin
        # Parse domain name
        name, new_offset = parse_domain_name(data, offset)
        return [nil, offset] if new_offset + 10 > data.bytesize
        
        # Parse TYPE, CLASS, TTL, and RDLENGTH
        rtype = data[new_offset, 2].unpack1('n')
        rclass = data[new_offset + 2, 2].unpack1('n')
        ttl = data[new_offset + 4, 4].unpack1('N')
        rdlength = data[new_offset + 8, 2].unpack1('n')
        
        new_offset += 10
        return [nil, offset] if new_offset + rdlength > data.bytesize
        
        rdata = data[new_offset, rdlength]
        
        record = {
          name: name,
          rtype: rtype,
          rclass: rclass,
          ttl: ttl,
          rdlength: rdlength,
          rdata: rdata,
          rtype_name: qtype_to_name(rtype)
        }
        
        [record, new_offset + rdlength]
      rescue => e
        puts "Resource record parsing error: #{e.message}"
        [nil, offset]
      end
    end

    def parse_domain_name(data, offset)
      name = ""
      original_offset = offset
      jumped = false
      
      while offset < data.bytesize
        length = data[offset].ord
        
        if length == 0
          offset += 1
          break
        elsif length & 0xC0 == 0xC0  # Compression pointer
          if !jumped
            original_offset = offset + 2
            jumped = true
          end
          offset = ((length & 0x3F) << 8) | data[offset + 1].ord
        else
          offset += 1
          break if offset + length > data.bytesize
          
          name += data[offset, length]
          name += "." unless data[offset + length]&.ord == 0
          offset += length
        end
      end
      
      [name.chomp('.'), jumped ? original_offset : offset]
    end

    def qtype_to_name(qtype)
      case qtype
      when 1 then :A
      when 2 then :NS
      when 5 then :CNAME
      when 6 then :SOA
      when 12 then :PTR
      when 15 then :MX
      when 16 then :TXT
      when 28 then :AAAA
      when 33 then :SRV
      else :unknown
      end
    end

    def qclass_to_name(qclass)
      case qclass
      when 1 then :IN
      when 2 then :CS
      when 3 then :CH
      when 4 then :HS
      else :unknown
      end
    end

    def calculate_entropy(string)
      return 0 if string.empty?
      
      frequencies = Hash.new(0)
      string.each_char { |char| frequencies[char] += 1 }
      
      entropy = 0
      length = string.length.to_f
      
      frequencies.each_value do |count|
        probability = count / length
        entropy -= probability * Math.log2(probability)
      end
      
      entropy
    end
  end

  # DNS Protocol handler for network appliance integration
  class DnsProtocol
    attr_reader :stats, :enabled

    def initialize(enable_logging: true, suspicious_threshold: 2)
      @enabled = true
      @enable_logging = enable_logging
      @suspicious_threshold = suspicious_threshold
      @mutex = Mutex.new
      
      @stats = {
        packets_processed: 0,
        queries_processed: 0,
        responses_processed: 0,
        parsing_errors: 0,
        suspicious_packets: 0,
        unique_domains: Set.new,
        response_codes: Hash.new(0),
        query_types: Hash.new(0)
      }
    end

    # Process DNS packet
    def process_dns_packet(udp_payload)
      return nil unless @enabled
      
      @mutex.synchronize { @stats[:packets_processed] += 1 }
      
      dns_packet = DnsPacket.new(udp_payload)
      
      unless dns_packet.header
        @mutex.synchronize { @stats[:parsing_errors] += 1 }
        return nil
      end
      
      # Update statistics
      @mutex.synchronize do
        if dns_packet.query?
          @stats[:queries_processed] += 1
          dns_packet.all_queried_domains.each { |domain| @stats[:unique_domains] << domain if domain }
          dns_packet.questions.each { |q| @stats[:query_types][q[:qtype_name]] += 1 }
        elsif dns_packet.response?
          @stats[:responses_processed] += 1
          @stats[:response_codes][dns_packet.header.response_code_name] += 1
        end
        
        # Check for suspicious characteristics
        if dns_packet.suspicious_characteristics.size >= @suspicious_threshold
          @stats[:suspicious_packets] += 1
        end
      end
      
      # Log if enabled
      if @enable_logging
        log_dns_packet(dns_packet)
      end
      
      dns_packet
    end

    # Enable/disable DNS processing
    def enabled=(state)
      @mutex.synchronize { @enabled = state }
    end

    # Get DNS processing statistics
    def dns_stats
      @mutex.synchronize do
        @stats.merge(
          unique_domain_count: @stats[:unique_domains].size,
          enabled: @enabled,
          suspicious_threshold: @suspicious_threshold
        )
      end
    end

    # Get top queried domains
    def top_domains(limit: 10)
      # Would need to track domain frequency for this
      @mutex.synchronize { @stats[:unique_domains].to_a.first(limit) }
    end

    # Reset statistics
    def reset_stats!
      @mutex.synchronize do
        @stats[:packets_processed] = 0
        @stats[:queries_processed] = 0
        @stats[:responses_processed] = 0
        @stats[:parsing_errors] = 0
        @stats[:suspicious_packets] = 0
        @stats[:unique_domains].clear
        @stats[:response_codes].clear
        @stats[:query_types].clear
      end
    end

    private

    def log_dns_packet(dns_packet)
      if dns_packet.query?
        puts "DNS Query: #{dns_packet.queried_domain} (#{dns_packet.header.transaction_id})"
      elsif dns_packet.response?
        ips = dns_packet.resolved_ips
        puts "DNS Response: #{dns_packet.queried_domain} -> #{ips.join(', ')} (#{dns_packet.header.transaction_id})"
      end
      
      # Log suspicious characteristics
      if dns_packet.suspicious_characteristics.any?
        puts "DNS SUSPICIOUS: #{dns_packet.suspicious_characteristics.join(', ')}"
      end
    end
  end
end
# frozen_string_literal: true

module AetherPacket
  # SignatureRule represents a single IDS detection rule
  # Supports hex patterns, string patterns, and positional matching
  class SignatureRule
    attr_reader :id, :name, :pattern, :pattern_type, :severity, :description, :metadata

    SEVERITY_LEVELS = {
      low: 1,
      medium: 2, 
      high: 3,
      critical: 4
    }.freeze

    def initialize(id:, name:, pattern:, pattern_type: :hex, severity: :medium, 
                   description: nil, offset: nil, depth: nil, **metadata)
      @id = id
      @name = name
      @pattern = pattern
      @pattern_type = pattern_type
      @severity = severity
      @description = description
      @offset = offset  # Start position for pattern search
      @depth = depth    # Maximum search depth
      @metadata = metadata
      
      @compiled_pattern = compile_pattern
      validate_rule!
    end

    # Check if pattern matches in data
    def match?(data)
      search_data = apply_position_constraints(data)
      return false unless search_data
      
      case @pattern_type
      when :hex
        search_data.include?(@compiled_pattern)
      when :string
        search_data.include?(@pattern)
      when :regex
        !(@compiled_pattern =~ search_data).nil?
      else
        false
      end
    end

    # Get rule severity as numeric value
    def severity_level
      SEVERITY_LEVELS[@severity] || SEVERITY_LEVELS[:medium]
    end

    # Check if rule is enabled
    def enabled?
      @metadata.fetch(:enabled, true)
    end

    # Rule information for logging
    def rule_info
      {
        id: @id,
        name: @name,
        severity: @severity,
        severity_level: severity_level,
        pattern_type: @pattern_type,
        description: @description,
        metadata: @metadata
      }
    end

    private

    def compile_pattern
      case @pattern_type
      when :hex
        # Convert hex string to binary
        hex_clean = @pattern.gsub(/[^0-9a-fA-F]/, '')
        [hex_clean].pack('H*')
      when :string
        @pattern
      when :regex
        Regexp.new(@pattern)
      else
        raise ArgumentError, "Unsupported pattern type: #{@pattern_type}"
      end
    end

    def apply_position_constraints(data)
      start_pos = @offset || 0
      return nil if start_pos >= data.bytesize
      
      end_pos = if @depth
        [@offset + @depth, data.bytesize].min
      else
        data.bytesize
      end
      
      data[start_pos...end_pos]
    end

    def validate_rule!
      raise ArgumentError, "Rule ID cannot be nil" unless @id
      raise ArgumentError, "Rule name cannot be empty" if @name.nil? || @name.empty?
      raise ArgumentError, "Pattern cannot be empty" if @pattern.nil? || @pattern.empty?
      raise ArgumentError, "Invalid severity level" unless SEVERITY_LEVELS.key?(@severity)
      
      if @pattern_type == :hex && @pattern.gsub(/[^0-9a-fA-F]/, '').length.odd?
        raise ArgumentError, "Hex pattern must have even number of hex digits"
      end
    end
  end

  # AlertEvent represents a triggered IDS alert
  class AlertEvent
    attr_reader :timestamp, :rule, :packet_info, :matched_data, :severity, :id

    def initialize(rule:, packet_info:, matched_data: nil)
      @id = SecureRandom.uuid
      @timestamp = Time.now
      @rule = rule
      @packet_info = packet_info
      @matched_data = matched_data
      @severity = rule.severity
    end

    # Convert alert to hash for logging/JSON
    def to_hash
      {
        id: @id,
        timestamp: @timestamp.iso8601,
        rule_id: @rule.id,
        rule_name: @rule.name,
        severity: @severity,
        severity_level: @rule.severity_level,
        packet_info: @packet_info,
        matched_data: @matched_data ? @matched_data.unpack1('H*') : nil,
        description: @rule.description
      }
    end

    # Format alert for human-readable output
    def format_alert
      "ALERT [#{@severity.upcase}] #{@rule.name} - #{@packet_info[:src_ip]} -> #{@packet_info[:dst_ip]}"
    end
  end

  # IdsPatternMatcher performs deep packet inspection with signature matching
  # Supports multiple pattern types and efficient batch processing
  class IdsPatternMatcher
    attr_reader :rules, :stats, :enabled

    def initialize(max_packet_size: 65535, alert_callback: nil)
      @rules = {}
      @rule_groups = Hash.new { |h, k| h[k] = [] }
      @max_packet_size = max_packet_size
      @alert_callback = alert_callback
      @enabled = true
      @mutex = Mutex.new
      
      @stats = {
        packets_inspected: 0,
        patterns_checked: 0,
        alerts_generated: 0,
        processing_time: 0,
        bytes_inspected: 0,
        rules_loaded: 0,
        false_positives: 0
      }
      
      load_default_rules
    end

    # Add new signature rule
    def add_rule(rule)
      @mutex.synchronize do
        @rules[rule.id] = rule
        @rule_groups[rule.severity] << rule
        @stats[:rules_loaded] += 1
      end
    end

    # Remove rule by ID
    def remove_rule(rule_id)
      @mutex.synchronize do
        rule = @rules.delete(rule_id)
        if rule
          @rule_groups[rule.severity].delete(rule)
          @stats[:rules_loaded] -= 1
          true
        else
          false
        end
      end
    end

    # Enable/disable pattern matching
    def enabled=(state)
      @mutex.synchronize { @enabled = state }
    end

    # Inspect packet payload for malicious patterns
    def inspect_packet(ipv4_packet, transport_packet, payload_data)
      return [] unless @enabled
      return [] if payload_data.nil? || payload_data.empty?
      
      start_time = Time.now
      alerts = []
      
      @mutex.synchronize do
        @stats[:packets_inspected] += 1
        @stats[:bytes_inspected] += payload_data.bytesize
        
        packet_info = extract_packet_info(ipv4_packet, transport_packet)
        
        # Check against all enabled rules
        @rules.values.each do |rule|
          next unless rule.enabled?
          
          @stats[:patterns_checked] += 1
          
          if rule.match?(payload_data)
            alert = AlertEvent.new(
              rule: rule,
              packet_info: packet_info,
              matched_data: extract_matched_data(payload_data, rule)
            )
            
            alerts << alert
            @stats[:alerts_generated] += 1
            
            # Trigger callback if configured
            @alert_callback&.call(alert)
          end
        end
        
        processing_time = Time.now - start_time
        @stats[:processing_time] += processing_time
      end
      
      alerts
    end

    # Bulk inspect multiple packets efficiently  
    def inspect_packets(packet_batch)
      return [] unless @enabled
      
      all_alerts = []
      
      packet_batch.each do |packet_data|
        ipv4_packet, transport_packet, payload = packet_data[:ipv4], packet_data[:transport], packet_data[:payload]
        alerts = inspect_packet(ipv4_packet, transport_packet, payload)
        all_alerts.concat(alerts)
      end
      
      all_alerts
    end

    # Get rules by severity level
    def rules_by_severity(severity)
      @mutex.synchronize { @rule_groups[severity].dup }
    end

    # Get inspection statistics
    def inspection_stats
      @mutex.synchronize do
        avg_processing_time = @stats[:processing_time] / [@stats[:packets_inspected], 1].max
        detection_rate = (@stats[:alerts_generated].to_f / [@stats[:packets_inspected], 1].max) * 100
        
        @stats.merge(
          avg_processing_time_ms: (avg_processing_time * 1000).round(3),
          detection_rate_percent: detection_rate.round(2),
          rules_by_severity: @rule_groups.transform_values(&:size),
          enabled: @enabled
        )
      end
    end

    # Reset all statistics
    def reset_stats!
      @mutex.synchronize do
        @stats.keys.each { |key| @stats[key] = 0 }
      end
    end

    # Load rules from configuration
    def load_rules_from_config(config)
      config.each do |rule_config|
        rule = SignatureRule.new(**rule_config)
        add_rule(rule)
      end
    end

    # Export all rules
    def export_rules
      @mutex.synchronize do
        @rules.values.map(&:rule_info)
      end
    end

    private

    def extract_packet_info(ipv4_packet, transport_packet)
      info = {
        src_ip: ipv4_packet.source_ip,
        dst_ip: ipv4_packet.destination_ip,
        protocol: ipv4_packet.protocol,
        packet_size: ipv4_packet.total_length
      }
      
      if transport_packet.respond_to?(:source_port)
        info.merge!(
          src_port: transport_packet.source_port,
          dst_port: transport_packet.destination_port
        )
      end
      
      info
    end

    def extract_matched_data(payload_data, rule)
      # Return small snippet of matched data for logging
      match_start = payload_data.index(rule.instance_variable_get(:@compiled_pattern))
      return nil unless match_start
      
      snippet_start = [match_start - 10, 0].max
      snippet_end = [match_start + 50, payload_data.bytesize].min
      payload_data[snippet_start...snippet_end]
    end

    # Load default threat detection rules
    def load_default_rules
      default_rules = [
        {
          id: 'malware_001',
          name: 'Generic Malware Signature',
          pattern: '4D5A90000300000004000000FFFF',  # PE header pattern
          pattern_type: :hex,
          severity: :high,
          description: 'Possible Windows PE executable in network traffic'
        },
        {
          id: 'shellcode_001', 
          name: 'x86 Shellcode Pattern',
          pattern: 'EB0E5F4F4F4F4F',  # Common shellcode NOP sled
          pattern_type: :hex,
          severity: :critical,
          description: 'Potential x86 shellcode execution attempt'
        },
        {
          id: 'sql_injection_001',
          name: 'SQL Injection Attempt',
          pattern: "' OR 1=1--",
          pattern_type: :string,
          severity: :high,
          description: 'Classic SQL injection attack pattern'
        },
        {
          id: 'xss_001',
          name: 'Cross-Site Scripting',
          pattern: '<script>',
          pattern_type: :string,
          severity: :medium,
          description: 'Potential XSS attack vector'
        },
        {
          id: 'command_injection_001',
          name: 'Command Injection',
          pattern: '; cat /etc/passwd',
          pattern_type: :string,
          severity: :high,
          description: 'Unix command injection attempt'
        },
        {
          id: 'backdoor_001',
          name: 'Backdoor Communication',
          pattern: 'X-Backdoor-Auth',
          pattern_type: :string,
          severity: :critical,
          description: 'Suspicious backdoor authentication header'
        }
      ]
      
      default_rules.each do |rule_config|
        rule = SignatureRule.new(**rule_config)
        add_rule(rule)
      end
    end
  end

  # IdsController manages IDS operations and rule sets
  class IdsController
    attr_reader :matcher, :alert_buffer, :enabled

    def initialize(buffer_size: 1000, **matcher_options)
      @matcher = IdsPatternMatcher.new(**matcher_options)
      @alert_buffer = []
      @buffer_size = buffer_size
      @enabled = true
      @mutex = Mutex.new
      
      # Set up alert callback to populate buffer
      @matcher.instance_variable_set(:@alert_callback, method(:handle_alert))
    end

    # Process packet through IDS inspection
    def process_packet(ipv4_packet, transport_packet, payload_data)
      return [] unless @enabled
      
      alerts = @matcher.inspect_packet(ipv4_packet, transport_packet, payload_data)
      log_alerts(alerts) if alerts.any?
      alerts
    end

    # Get recent alerts from buffer
    def recent_alerts(count: 50)
      @mutex.synchronize { @alert_buffer.last(count) }
    end

    # Clear alert buffer
    def clear_alerts!
      @mutex.synchronize { @alert_buffer.clear }
    end

    # Enable/disable IDS processing
    def enabled=(state)
      @enabled = state
      @matcher.enabled = state
    end

    # Get comprehensive IDS statistics
    def ids_stats
      @matcher.inspection_stats.merge(
        alert_buffer_size: @alert_buffer.size,
        max_buffer_size: @buffer_size,
        controller_enabled: @enabled
      )
    end

    # Add custom detection rule
    def add_detection_rule(**rule_params)
      rule = SignatureRule.new(**rule_params)
      @matcher.add_rule(rule)
    end

    private

    def handle_alert(alert)
      @mutex.synchronize do
        @alert_buffer << alert
        
        # Maintain buffer size limit
        if @alert_buffer.size > @buffer_size
          @alert_buffer.shift
        end
      end
    end

    def log_alerts(alerts)
      alerts.each do |alert|
        puts "IDS ALERT: #{alert.format_alert} at #{alert.timestamp}"
      end
    end
  end
end
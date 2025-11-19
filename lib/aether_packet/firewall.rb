# frozen_string_literal: true

module AetherPacket
  # Firewall implements stateless packet filtering with 5-tuple matching
  # Provides allow/deny rules for comprehensive traffic control
  class Firewall
    # Firewall actions
    ACTION_ALLOW = :allow
    ACTION_DENY = :deny
    ACTION_DROP = :drop
    ACTION_REJECT = :reject

    # Rule matching results
    MATCH_ALLOW = :allow
    MATCH_DENY = :deny
    MATCH_NO_MATCH = :no_match

    # Firewall rule structure
    FirewallRule = Struct.new(
      :id, :name, :action, :direction, :protocol, :source_ip, :source_port,
      :destination_ip, :destination_port, :created_at, :hit_count, :enabled
    ) do
      def initialize(*)
        super
        self.hit_count = 0
        self.enabled = true
        self.created_at = Time.now
      end

      def matches?(packet_info)
        return false unless enabled

        # Check direction
        return false if direction && direction != packet_info[:direction]
        
        # Check protocol
        return false if protocol && protocol != packet_info[:protocol]
        
        # Check source IP
        return false if source_ip && !ip_matches?(source_ip, packet_info[:source_ip])
        
        # Check destination IP  
        return false if destination_ip && !ip_matches?(destination_ip, packet_info[:destination_ip])
        
        # Check source port
        return false if source_port && !port_matches?(source_port, packet_info[:source_port])
        
        # Check destination port
        return false if destination_port && !port_matches?(destination_port, packet_info[:destination_port])
        
        true
      end

      def increment_hit_count!
        self.hit_count += 1
      end

      private

      # Check if IP address/network matches
      def ip_matches?(rule_ip, packet_ip)
        return true if rule_ip == "any" || rule_ip == "0.0.0.0/0"
        
        if rule_ip.include?("/")
          # CIDR notation
          network, prefix = rule_ip.split("/")
          prefix_length = prefix.to_i
          
          rule_network_int = IPv4Packet.string_to_ip(network)
          packet_ip_int = IPv4Packet.string_to_ip(packet_ip)
          netmask = (0xffffffff << (32 - prefix_length)) & 0xffffffff
          
          (rule_network_int & netmask) == (packet_ip_int & netmask)
        else
          # Single IP
          rule_ip == packet_ip
        end
      rescue
        false
      end

      # Check if port/port range matches
      def port_matches?(rule_port, packet_port)
        return true if rule_port == "any"
        
        case rule_port
        when Integer
          rule_port == packet_port
        when String
          if rule_port.include?("-")
            # Port range
            start_port, end_port = rule_port.split("-").map(&:to_i)
            packet_port >= start_port && packet_port <= end_port
          else
            rule_port.to_i == packet_port
          end
        when Range
          rule_port.include?(packet_port)
        else
          false
        end
      rescue
        false
      end
    end

    attr_reader :rules, :default_policy, :stats

    def initialize(default_policy: ACTION_DENY)
      @rules = []
      @default_policy = default_policy
      @next_rule_id = 1
      
      @stats = {
        packets_processed: 0,
        packets_allowed: 0,
        packets_denied: 0,
        rule_hits: 0,
        default_policy_hits: 0,
        last_reset: Time.now
      }
    end

    # Add firewall rule
    def add_rule(name:, action:, direction: nil, protocol: nil, source_ip: nil, 
                source_port: nil, destination_ip: nil, destination_port: nil)
      
      rule = FirewallRule.new(
        @next_rule_id,
        name,
        action,
        direction,
        protocol,
        source_ip,
        source_port,
        destination_ip,
        destination_port
      )
      
      @rules << rule
      @next_rule_id += 1
      rule
    end

    # Remove firewall rule
    def remove_rule(rule_id)
      @rules.reject! { |rule| rule.id == rule_id }
    end

    # Enable/disable rule
    def enable_rule(rule_id)
      rule = find_rule(rule_id)
      rule.enabled = true if rule
    end

    def disable_rule(rule_id)
      rule = find_rule(rule_id)
      rule.enabled = false if rule
    end

    # Process packet through firewall
    def process_packet(ipv4_packet, transport_packet, direction = :inbound)
      @stats[:packets_processed] += 1
      
      packet_info = extract_packet_info(ipv4_packet, transport_packet, direction)
      
      # Check rules in order
      @rules.each do |rule|
        if rule.matches?(packet_info)
          rule.increment_hit_count!
          @stats[:rule_hits] += 1
          
          result = execute_rule_action(rule.action, packet_info)
          update_stats(result)
          return result
        end
      end
      
      # No rule matched, apply default policy
      @stats[:default_policy_hits] += 1
      result = execute_rule_action(@default_policy, packet_info)
      update_stats(result)
      result
    end

    # Check if packet is allowed (without processing)
    def packet_allowed?(ipv4_packet, transport_packet, direction = :inbound)
      result = process_packet(ipv4_packet, transport_packet, direction)
      result[:action] == ACTION_ALLOW
    end

    # Get firewall statistics
    def firewall_stats
      @stats.merge(
        total_rules: @rules.size,
        enabled_rules: @rules.count(&:enabled),
        disabled_rules: @rules.count { |r| !r.enabled },
        default_policy: @default_policy,
        rule_hit_distribution: rule_hit_distribution,
        top_rules: top_rules_by_hits(5)
      )
    end

    # Get rules by criteria
    def find_rules(action: nil, protocol: nil, enabled: nil)
      filtered_rules = @rules
      
      filtered_rules = filtered_rules.select { |r| r.action == action } if action
      filtered_rules = filtered_rules.select { |r| r.protocol == protocol } if protocol
      filtered_rules = filtered_rules.select { |r| r.enabled == enabled } unless enabled.nil?
      
      filtered_rules
    end

    # Clear all rules
    def clear_rules!
      @rules.clear
      @next_rule_id = 1
    end

    # Set default policy
    def set_default_policy(policy)
      @default_policy = policy
    end

    # Import rules from configuration
    def import_rules(rules_config)
      imported_count = 0
      
      rules_config.each do |rule_config|
        begin
          add_rule(
            name: rule_config[:name],
            action: rule_config[:action].to_sym,
            direction: rule_config[:direction]&.to_sym,
            protocol: rule_config[:protocol]&.to_sym,
            source_ip: rule_config[:source_ip],
            source_port: rule_config[:source_port],
            destination_ip: rule_config[:destination_ip],
            destination_port: rule_config[:destination_port]
          )
          imported_count += 1
        rescue => e
          # Log error and continue with next rule
          puts "Error importing rule #{rule_config[:name]}: #{e.message}"
        end
      end
      
      imported_count
    end

    # Export rules to configuration
    def export_rules
      @rules.map do |rule|
        {
          id: rule.id,
          name: rule.name,
          action: rule.action,
          direction: rule.direction,
          protocol: rule.protocol,
          source_ip: rule.source_ip,
          source_port: rule.source_port,
          destination_ip: rule.destination_ip,
          destination_port: rule.destination_port,
          hit_count: rule.hit_count,
          enabled: rule.enabled,
          created_at: rule.created_at
        }
      end
    end

    # Reset statistics
    def reset_stats!
      @stats[:packets_processed] = 0
      @stats[:packets_allowed] = 0
      @stats[:packets_denied] = 0
      @stats[:rule_hits] = 0
      @stats[:default_policy_hits] = 0
      @stats[:last_reset] = Time.now
      
      @rules.each { |rule| rule.hit_count = 0 }
    end

    private

    # Extract packet information for rule matching
    def extract_packet_info(ipv4_packet, transport_packet, direction)
      source_port = 0
      destination_port = 0
      protocol = :ip
      
      case transport_packet
      when TcpSegment
        protocol = :tcp
        source_port = transport_packet.source_port
        destination_port = transport_packet.destination_port
      when UdpDatagram
        protocol = :udp
        source_port = transport_packet.source_port
        destination_port = transport_packet.destination_port
      when IcmpPacket
        protocol = :icmp
        # ICMP doesn't have ports, but we can use type/code
        source_port = transport_packet.type
        destination_port = transport_packet.code
      end
      
      {
        direction: direction,
        protocol: protocol,
        source_ip: ipv4_packet.source_ip_string,
        source_port: source_port,
        destination_ip: ipv4_packet.destination_ip_string,
        destination_port: destination_port
      }
    end

    # Execute rule action
    def execute_rule_action(action, packet_info)
      case action
      when ACTION_ALLOW
        { action: ACTION_ALLOW, reason: "Rule matched - ALLOW" }
      when ACTION_DENY, ACTION_DROP
        { action: ACTION_DENY, reason: "Rule matched - DENY/DROP" }
      when ACTION_REJECT
        { action: ACTION_REJECT, reason: "Rule matched - REJECT" }
      else
        { action: ACTION_DENY, reason: "Unknown action - default DENY" }
      end
    end

    # Update firewall statistics
    def update_stats(result)
      case result[:action]
      when ACTION_ALLOW
        @stats[:packets_allowed] += 1
      when ACTION_DENY, ACTION_DROP, ACTION_REJECT
        @stats[:packets_denied] += 1
      end
    end

    # Find rule by ID
    def find_rule(rule_id)
      @rules.find { |rule| rule.id == rule_id }
    end

    # Get rule hit distribution
    def rule_hit_distribution
      distribution = {}
      @rules.each { |rule| distribution[rule.id] = rule.hit_count }
      distribution
    end

    # Get top rules by hit count
    def top_rules_by_hits(count = 5)
      @rules.sort_by { |rule| -rule.hit_count }.first(count).map do |rule|
        {
          id: rule.id,
          name: rule.name,
          hit_count: rule.hit_count,
          action: rule.action
        }
      end
    end
  end
end
# frozen_string_literal: true

module AetherPacket
  # StatefulFirewall extends basic firewall with connection tracking
  # Automatically allows return traffic for established connections
  class StatefulFirewall < Firewall
    attr_reader :connection_tracker, :stateful_rules

    def initialize(default_policy: ACTION_DENY, enable_stateful: true)
      super(default_policy: default_policy)
      @enable_stateful = enable_stateful
      @connection_tracker = ConnectionTable.new
      
      # Stateful rule tracking
      @stateful_rules = {}  # rule_id -> stateful_config
      
      # Enhanced statistics
      @stats.merge!(
        stateful_allows: 0,
        new_connections: 0,
        established_connections: 0,
        connection_timeouts: 0,
        stateful_denies: 0
      )
    end

    # Process packet with stateful analysis
    def process_packet(ipv4_packet, transport_packet, direction = :inbound)
      @stats[:packets_processed] += 1
      
      packet_info = extract_packet_info(ipv4_packet, transport_packet, direction)
      
      if @enable_stateful
        # Check if packet belongs to established connection
        connection_result = check_established_connection(ipv4_packet, transport_packet, direction)
        if connection_result[:established]
          @stats[:established_connections] += 1
          @stats[:stateful_allows] += 1
          return { action: ACTION_ALLOW, reason: "Established connection", connection: connection_result[:connection] }
        end
      end
      
      # Process through regular firewall rules
      rule_result = process_firewall_rules(packet_info)
      
      if @enable_stateful && rule_result[:action] == ACTION_ALLOW
        # Track new connection if allowed
        connection = @connection_tracker.track_connection(ipv4_packet, transport_packet)
        if connection
          @stats[:new_connections] += 1
          rule_result[:connection] = connection
        end
      end
      
      update_stats(rule_result)
      rule_result
    end

    # Add stateful rule (automatically allows return traffic)
    def add_stateful_rule(name:, action:, direction: nil, protocol: nil, source_ip: nil,
                         source_port: nil, destination_ip: nil, destination_port: nil,
                         track_connection: true, connection_timeout: nil)
      
      rule = add_rule(
        name: name,
        action: action,
        direction: direction,
        protocol: protocol,
        source_ip: source_ip,
        source_port: source_port,
        destination_ip: destination_ip,
        destination_port: destination_port
      )
      
      if track_connection && action == ACTION_ALLOW
        @stateful_rules[rule.id] = {
          track_connection: track_connection,
          connection_timeout: connection_timeout,
          reverse_allow: true
        }
      end
      
      rule
    end

    # Get stateful firewall statistics
    def stateful_stats
      connection_stats = @connection_tracker.connection_stats
      
      firewall_stats.merge(
        connection_stats: connection_stats,
        stateful_rules_count: @stateful_rules.size,
        stateful_enabled: @enable_stateful
      )
    end

    # Get active connections
    def active_connections
      @connection_tracker.active_connections
    end

    # Clean up expired connections
    def cleanup_connections!
      expired = @connection_tracker.cleanup_expired_connections!
      @stats[:connection_timeouts] += expired
      expired
    end

    # Enable/disable stateful tracking
    def enable_stateful!
      @enable_stateful = true
    end

    def disable_stateful!
      @enable_stateful = false
    end

    # Check connection state for packet
    def connection_state(ipv4_packet, transport_packet)
      return nil unless @enable_stateful
      
      tuple = extract_connection_tuple(ipv4_packet, transport_packet)
      @connection_tracker.lookup_connection(tuple)
    end

    # Add connection manually (for integration with NAT)
    def track_connection(ipv4_packet, transport_packet)
      return nil unless @enable_stateful
      @connection_tracker.track_connection(ipv4_packet, transport_packet)
    end

    # Check if packet is part of established connection
    def established_connection?(ipv4_packet, transport_packet)
      connection = connection_state(ipv4_packet, transport_packet)
      connection && connection.state == :established
    end

    # Get connection by tuple
    def find_connection(source_ip:, source_port:, destination_ip:, destination_port:, protocol:)
      tuple = {
        protocol: protocol,
        source_ip: source_ip,
        source_port: source_port,
        destination_ip: destination_ip,
        destination_port: destination_port
      }
      
      @connection_tracker.lookup_connection(tuple)
    end

    private

    # Check if packet belongs to established connection
    def check_established_connection(ipv4_packet, transport_packet, direction)
      tuple = extract_connection_tuple(ipv4_packet, transport_packet)
      connection = @connection_tracker.lookup_connection(tuple)
      
      if connection && !connection.expired?
        # Update connection activity
        connection.update_activity!(ipv4_packet.total_length, 
                                  direction == :outbound ? :outbound : :inbound)
        
        return { established: true, connection: connection }
      end
      
      # Check reverse direction for established connections
      reverse_tuple = {
        protocol: tuple[:protocol],
        source_ip: tuple[:destination_ip],
        source_port: tuple[:destination_port], 
        destination_ip: tuple[:source_ip],
        destination_port: tuple[:source_port]
      }
      
      reverse_connection = @connection_tracker.lookup_connection(reverse_tuple)
      
      if reverse_connection && !reverse_connection.expired?
        # This is return traffic for an established connection
        reverse_connection.update_activity!(ipv4_packet.total_length,
                                          direction == :outbound ? :inbound : :outbound)
        
        return { established: true, connection: reverse_connection }
      end
      
      { established: false, connection: nil }
    end

    # Process packet through firewall rules
    def process_firewall_rules(packet_info)
      # Check rules in order
      @rules.each do |rule|
        if rule.matches?(packet_info)
          rule.increment_hit_count!
          @stats[:rule_hits] += 1
          
          result = execute_rule_action(rule.action, packet_info)
          result[:rule_id] = rule.id
          return result
        end
      end
      
      # No rule matched, apply default policy
      @stats[:default_policy_hits] += 1
      result = execute_rule_action(@default_policy, packet_info)
      result[:rule_id] = nil
      result
    end

    # Extract connection tuple from packets
    def extract_connection_tuple(ipv4_packet, transport_packet)
      {
        protocol: get_protocol_symbol(transport_packet),
        source_ip: ipv4_packet.source_ip_string,
        source_port: get_source_port(transport_packet),
        destination_ip: ipv4_packet.destination_ip_string,
        destination_port: get_destination_port(transport_packet)
      }
    end

    # Get protocol symbol
    def get_protocol_symbol(transport_packet)
      case transport_packet
      when TcpSegment then :tcp
      when UdpDatagram then :udp
      when IcmpPacket then :icmp
      else :ip
      end
    end

    # Get source port from transport packet
    def get_source_port(transport_packet)
      case transport_packet
      when TcpSegment, UdpDatagram
        transport_packet.source_port
      when IcmpPacket
        transport_packet.type
      else
        0
      end
    end

    # Get destination port from transport packet
    def get_destination_port(transport_packet)
      case transport_packet
      when TcpSegment, UdpDatagram
        transport_packet.destination_port
      when IcmpPacket
        transport_packet.code
      else
        0
      end
    end
  end

  # FirewallManager integrates firewall with network appliance
  # Provides centralized firewall management for the entire system
  class FirewallManager
    attr_reader :firewalls, :global_stats

    def initialize
      @firewalls = {}  # interface_name -> firewall
      @global_firewall = StatefulFirewall.new
      @global_stats = {
        total_packets: 0,
        total_allowed: 0,
        total_denied: 0,
        interfaces_protected: 0
      }
    end

    # Add firewall for specific interface
    def add_interface_firewall(interface_name, firewall = nil)
      @firewalls[interface_name] = firewall || StatefulFirewall.new
      @global_stats[:interfaces_protected] = @firewalls.size
    end

    # Process packet through appropriate firewall
    def process_packet(ipv4_packet, transport_packet, interface_name = nil, direction = :inbound)
      @global_stats[:total_packets] += 1
      
      firewall = @firewalls[interface_name] || @global_firewall
      result = firewall.process_packet(ipv4_packet, transport_packet, direction)
      
      case result[:action]
      when Firewall::ACTION_ALLOW
        @global_stats[:total_allowed] += 1
      else
        @global_stats[:total_denied] += 1
      end
      
      result
    end

    # Add rule to specific interface or global firewall
    def add_rule(interface_name: nil, **rule_options)
      firewall = @firewalls[interface_name] || @global_firewall
      
      if firewall.is_a?(StatefulFirewall) && rule_options[:stateful]
        firewall.add_stateful_rule(**rule_options.except(:stateful))
      else
        firewall.add_rule(**rule_options.except(:stateful))
      end
    end

    # Get comprehensive firewall statistics
    def firewall_statistics
      interface_stats = {}
      @firewalls.each do |interface, firewall|
        interface_stats[interface] = firewall.stateful_stats
      end
      
      global_firewall_stats = @global_firewall.stateful_stats
      
      @global_stats.merge(
        global_firewall: global_firewall_stats,
        interface_firewalls: interface_stats,
        total_rules: total_rule_count,
        total_connections: total_connection_count
      )
    end

    # Cleanup all firewalls
    def cleanup_all!
      cleanup_count = 0
      
      @firewalls.each_value do |firewall|
        cleanup_count += firewall.cleanup_connections! if firewall.respond_to?(:cleanup_connections!)
      end
      
      cleanup_count += @global_firewall.cleanup_connections!
      cleanup_count
    end

    private

    # Count total rules across all firewalls
    def total_rule_count
      count = @global_firewall.rules.size
      @firewalls.each_value { |firewall| count += firewall.rules.size }
      count
    end

    # Count total connections across all firewalls
    def total_connection_count
      count = @global_firewall.active_connections.size
      @firewalls.each_value do |firewall|
        count += firewall.active_connections.size if firewall.respond_to?(:active_connections)
      end
      count
    end
  end
end
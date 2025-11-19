# frozen_string_literal: true

module AetherPacket
  # StatefulNatEngine integrates SNAT/DNAT with connection tracking
  # Provides comprehensive NAT functionality with stateful connection management
  class StatefulNatEngine
    attr_reader :snat_engine, :connection_table, :port_forwarding_rules, :stats

    def initialize(external_ip:, internal_networks:, port_range: 10000..65000)
      @snat_engine = NatEngine.new(external_ip: external_ip, port_range: port_range)
      @connection_table = ConnectionTable.new
      @internal_networks = internal_networks
      @external_ip = external_ip
      
      # Port forwarding rules (DNAT)
      @port_forwarding_rules = {}  # external_port -> {internal_ip:, internal_port:, protocol:}
      
      # Reverse NAT mappings (for established connections)
      @reverse_mappings = {}  # external_tuple_hash -> internal_tuple
      
      @stats = {
        snat_packets: 0,
        dnat_packets: 0,
        port_forwarding_hits: 0,
        connection_nat_mappings: 0,
        reverse_nat_packets: 0,
        nat_failures: 0
      }
    end

    # Add port forwarding rule (DNAT)
    def add_port_forwarding(external_port:, internal_ip:, internal_port:, protocol: :tcp)
      rule_key = "#{external_port}/#{protocol}"
      @port_forwarding_rules[rule_key] = {
        internal_ip: internal_ip,
        internal_port: internal_port,
        protocol: protocol,
        created_at: Time.now,
        hit_count: 0
      }
    end

    # Remove port forwarding rule
    def remove_port_forwarding(external_port:, protocol: :tcp)
      rule_key = "#{external_port}/#{protocol}"
      @port_forwarding_rules.delete(rule_key)
    end

    # Process outbound packet (apply SNAT)
    def process_outbound_packet(ethernet_frame, ipv4_packet, transport_packet)
      return nil unless should_apply_snat?(ipv4_packet)

      # Track connection first
      connection = @connection_table.track_connection(ipv4_packet, transport_packet)
      
      # Apply SNAT
      snat_result = @snat_engine.snat_packet(ipv4_packet, transport_packet)
      return nil unless snat_result

      # Link NAT mapping with connection
      if connection && snat_result
        nat_mapping = @snat_engine.get_mapping_for_connection(
          extract_connection_tuple(ipv4_packet, transport_packet)
        )
        
        if nat_mapping
          connection.nat_mapping = nat_mapping
          
          # Create reverse mapping for return packets
          create_reverse_mapping(nat_mapping, connection)
          @stats[:connection_nat_mappings] += 1
        end
      end

      @stats[:snat_packets] += 1
      
      # Rebuild Ethernet frame with NAT'd packet
      rebuild_ethernet_frame(ethernet_frame, ipv4_packet)
    end

    # Process inbound packet (apply DNAT or reverse NAT)
    def process_inbound_packet(ethernet_frame, ipv4_packet, transport_packet)
      return nil unless packet_for_us?(ipv4_packet)

      # Try port forwarding first (for new connections)
      dnat_result = try_port_forwarding(ipv4_packet, transport_packet)
      if dnat_result
        @stats[:dnat_packets] += 1
        @stats[:port_forwarding_hits] += 1
        return rebuild_ethernet_frame(ethernet_frame, ipv4_packet)
      end

      # Try reverse NAT (for established connections)
      reverse_result = try_reverse_nat(ipv4_packet, transport_packet)
      if reverse_result
        @stats[:reverse_nat_packets] += 1
        return rebuild_ethernet_frame(ethernet_frame, ipv4_packet)
      end

      # Try SNAT engine's DNAT for existing mappings
      snat_dnat_result = @snat_engine.dnat_packet(ipv4_packet, transport_packet)
      if snat_dnat_result
        @stats[:dnat_packets] += 1
        return rebuild_ethernet_frame(ethernet_frame, ipv4_packet)
      end

      @stats[:nat_failures] += 1
      nil
    end

    # Get NAT statistics
    def nat_statistics
      base_stats = @snat_engine.nat_stats
      connection_stats = @connection_table.connection_stats
      
      @stats.merge(base_stats).merge(
        connection_stats: connection_stats,
        port_forwarding_rules: @port_forwarding_rules.size,
        reverse_mappings: @reverse_mappings.size,
        total_nat_packets: @stats[:snat_packets] + @stats[:dnat_packets],
        nat_success_rate: calculate_nat_success_rate
      )
    end

    # Clean up expired mappings and connections
    def cleanup!
      # Clean up expired connections
      expired_connections = @connection_table.cleanup_expired_connections!
      
      # Clean up expired NAT mappings
      expired_mappings = @snat_engine.cleanup_expired_mappings!
      
      # Clean up orphaned reverse mappings
      cleanup_reverse_mappings!
      
      {
        expired_connections: expired_connections,
        expired_mappings: expired_mappings,
        cleaned_reverse_mappings: cleanup_reverse_mappings!
      }
    end

    # Get active NAT sessions
    def active_nat_sessions
      sessions = []
      
      @connection_table.active_connections.each do |connection|
        next unless connection.nat_mapping
        
        sessions << {
          connection_id: connection.id,
          protocol: connection.protocol,
          state: connection.state,
          internal_endpoint: "#{connection.source_ip}:#{connection.source_port}",
          external_endpoint: "#{connection.nat_mapping.external_ip}:#{connection.nat_mapping.external_port}",
          destination: "#{connection.destination_ip}:#{connection.destination_port}",
          bytes_sent: connection.bytes_sent,
          bytes_received: connection.bytes_received,
          duration: Time.now - connection.created_at
        }
      end
      
      sessions
    end

    # Check if connection exists for tuple
    def connection_exists?(source_ip:, source_port:, destination_ip:, destination_port:, protocol:)
      tuple = {
        protocol: protocol,
        source_ip: source_ip,
        source_port: source_port,
        destination_ip: destination_ip,
        destination_port: destination_port
      }
      
      connection = @connection_table.lookup_connection(tuple)
      connection && !connection.expired?
    end

    # Get connection information
    def get_connection_info(connection_tuple)
      @connection_table.lookup_connection(connection_tuple)
    end

    private

    # Check if outbound packet should be SNAT'd
    def should_apply_snat?(ipv4_packet)
      source_ip = ipv4_packet.source_ip_string
      dest_ip = ipv4_packet.destination_ip_string
      
      # Source is internal and destination is external
      internal_network?(source_ip) && !internal_network?(dest_ip)
    end

    # Check if packet is destined for us (external IP)
    def packet_for_us?(ipv4_packet)
      ipv4_packet.destination_ip_string == @external_ip
    end

    # Check if IP is in internal networks
    def internal_network?(ip_address)
      return false unless ip_address
      
      ip_int = IPv4Packet.string_to_ip(ip_address)
      
      @internal_networks.any? do |network, prefix_length|
        network_int = IPv4Packet.string_to_ip(network)
        netmask = (0xffffffff << (32 - prefix_length)) & 0xffffffff
        (ip_int & netmask) == (network_int & netmask)
      end
    end

    # Try port forwarding for inbound packet
    def try_port_forwarding(ipv4_packet, transport_packet)
      return nil unless transport_packet.respond_to?(:destination_port)
      
      dest_port = transport_packet.destination_port
      protocol = transport_packet.is_a?(TcpSegment) ? :tcp : :udp
      rule_key = "#{dest_port}/#{protocol}"
      
      rule = @port_forwarding_rules[rule_key]
      return nil unless rule
      
      # Apply DNAT
      original_dest_ip = ipv4_packet.destination_ip_string
      ipv4_packet.destination_ip = IPv4Packet.string_to_ip(rule[:internal_ip])
      transport_packet.destination_port = rule[:internal_port]
      
      # Update checksums
      update_packet_checksums(ipv4_packet, transport_packet)
      
      # Update rule statistics
      rule[:hit_count] += 1
      
      {
        action: :port_forwarding,
        external_port: dest_port,
        internal_ip: rule[:internal_ip],
        internal_port: rule[:internal_port],
        original_destination: original_dest_ip
      }
    end

    # Try reverse NAT for established connections
    def try_reverse_nat(ipv4_packet, transport_packet)
      external_tuple = extract_external_tuple(ipv4_packet, transport_packet)
      internal_tuple = @reverse_mappings[hash_tuple(external_tuple)]
      
      return nil unless internal_tuple
      
      # Apply reverse NAT
      ipv4_packet.destination_ip = IPv4Packet.string_to_ip(internal_tuple[:ip])
      
      if transport_packet.respond_to?(:destination_port)
        transport_packet.destination_port = internal_tuple[:port]
      end
      
      # Update checksums
      update_packet_checksums(ipv4_packet, transport_packet)
      
      {
        action: :reverse_nat,
        internal_ip: internal_tuple[:ip],
        internal_port: internal_tuple[:port]
      }
    end

    # Create reverse mapping for established connection
    def create_reverse_mapping(nat_mapping, connection)
      external_tuple = {
        ip: nat_mapping.external_ip,
        port: nat_mapping.external_port,
        protocol: nat_mapping.protocol
      }
      
      internal_tuple = {
        ip: nat_mapping.internal_ip,
        port: nat_mapping.internal_port,
        protocol: nat_mapping.protocol
      }
      
      @reverse_mappings[hash_tuple(external_tuple)] = internal_tuple
    end

    # Clean up orphaned reverse mappings
    def cleanup_reverse_mappings!
      cleanup_count = 0
      
      @reverse_mappings.delete_if do |tuple_hash, internal_tuple|
        # Check if corresponding connection still exists
        connection_exists = @connection_table.active_connections.any? do |conn|
          conn.source_ip == internal_tuple[:ip] &&
          conn.source_port == internal_tuple[:port] &&
          conn.protocol == internal_tuple[:protocol]
        end
        
        unless connection_exists
          cleanup_count += 1
          true
        else
          false
        end
      end
      
      cleanup_count
    end

    # Extract connection tuple from packets
    def extract_connection_tuple(ipv4_packet, transport_packet)
      {
        protocol: get_transport_protocol(transport_packet),
        source_ip: ipv4_packet.source_ip_string,
        source_port: get_source_port(transport_packet),
        destination_ip: ipv4_packet.destination_ip_string,
        destination_port: get_destination_port(transport_packet)
      }
    end

    # Extract external tuple for reverse lookup
    def extract_external_tuple(ipv4_packet, transport_packet)
      {
        ip: ipv4_packet.destination_ip_string,
        port: get_destination_port(transport_packet),
        protocol: get_transport_protocol(transport_packet)
      }
    end

    # Get transport protocol
    def get_transport_protocol(transport_packet)
      case transport_packet
      when TcpSegment then :tcp
      when UdpDatagram then :udp
      else :icmp
      end
    end

    # Get source port from transport packet
    def get_source_port(transport_packet)
      transport_packet.respond_to?(:source_port) ? transport_packet.source_port : 0
    end

    # Get destination port from transport packet
    def get_destination_port(transport_packet)
      transport_packet.respond_to?(:destination_port) ? transport_packet.destination_port : 0
    end

    # Hash tuple for lookups
    def hash_tuple(tuple)
      "#{tuple[:ip]}:#{tuple[:port]}/#{tuple[:protocol]}"
    end

    # Update packet checksums after NAT
    def update_packet_checksums(ipv4_packet, transport_packet)
      # Update IP checksum
      ipv4_packet.update_checksum!
      
      # Update transport checksum
      case transport_packet
      when TcpSegment
        transport_packet.update_checksum!(ipv4_packet.source_ip, ipv4_packet.destination_ip)
      when UdpDatagram
        transport_packet.update_checksum!(ipv4_packet.source_ip, ipv4_packet.destination_ip)
      end
    end

    # Rebuild Ethernet frame with modified IP packet
    def rebuild_ethernet_frame(original_frame, modified_ipv4_packet)
      EthernetFrame.create(
        destination_mac: original_frame.destination_mac_string,
        source_mac: original_frame.source_mac_string,
        ethertype: original_frame.actual_ethertype,
        payload: modified_ipv4_packet.to_binary_s,
        vlan_id: original_frame.vlan_tagged? ? original_frame.vlan_id : nil
      ).to_binary_s
    end

    # Calculate NAT success rate
    def calculate_nat_success_rate
      total_attempts = @stats[:snat_packets] + @stats[:dnat_packets] + @stats[:nat_failures]
      return 0 if total_attempts == 0
      
      successful = @stats[:snat_packets] + @stats[:dnat_packets]
      (successful.to_f / total_attempts) * 100
    end
  end
end
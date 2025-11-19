# frozen_string_literal: true

module AetherPacket
  # NatEngine implements Source Network Address Translation (SNAT)
  # Rewrites outgoing source IPs to router's external IP and tracks mappings
  class NatEngine
    # NAT mapping entry structure
    NatMapping = Struct.new(
      :internal_ip, :internal_port, :external_ip, :external_port,
      :protocol, :created_at, :last_used, :connection_id, :timeout
    ) do
      def expired?(current_time = Time.now)
        current_time - last_used > timeout
      end

      def update_activity!
        self.last_used = Time.now
      end

      def external_tuple
        {
          ip: external_ip,
          port: external_port,
          protocol: protocol
        }
      end

      def internal_tuple
        {
          ip: internal_ip,
          port: internal_port,
          protocol: protocol
        }
      end
    end

    attr_reader :mappings, :external_ip, :port_pool, :stats

    def initialize(external_ip:, port_range: 10000..65000)
      @external_ip = external_ip
      @port_range = port_range
      @port_pool = PortPool.new(port_range)
      
      # NAT mapping tables
      @mappings = {}  # mapping_id -> NatMapping
      @internal_lookup = {}  # internal_tuple_hash -> mapping_id
      @external_lookup = {}  # external_tuple_hash -> mapping_id
      
      # Default timeouts (seconds)
      @timeouts = {
        tcp_established: 7200,  # 2 hours
        tcp_syn_sent: 120,      # 2 minutes
        tcp_fin_wait: 240,      # 4 minutes
        udp_active: 300,        # 5 minutes
        udp_reply: 60,          # 1 minute
        icmp: 60                # 1 minute
      }

      @stats = {
        mappings_created: 0,
        mappings_expired: 0,
        packets_snat: 0,
        packets_dnat: 0,
        port_exhaustion: 0,
        last_cleanup: Time.now
      }
    end

    # Perform Source NAT on outgoing packet
    def snat_packet(ipv4_packet, transport_packet)
      return nil unless should_nat_outgoing?(ipv4_packet)

      # Get or create NAT mapping
      mapping = get_or_create_mapping(ipv4_packet, transport_packet, :outbound)
      return nil unless mapping

      # Rewrite source IP and port
      original_source_ip = ipv4_packet.source_ip_string
      original_source_port = get_source_port(transport_packet)

      ipv4_packet.source_ip = IPv4Packet.string_to_ip(@external_ip)
      set_source_port(transport_packet, mapping.external_port) if transport_packet

      # Recalculate checksums
      update_checksums(ipv4_packet, transport_packet)
      
      # Update mapping activity
      mapping.update_activity!
      @stats[:packets_snat] += 1

      {
        action: :snat_applied,
        mapping_id: mapping.object_id,
        original_ip: original_source_ip,
        original_port: original_source_port,
        external_ip: @external_ip,
        external_port: mapping.external_port
      }
    end

    # Perform Destination NAT on incoming packet
    def dnat_packet(ipv4_packet, transport_packet)
      return nil unless nat_for_us?(ipv4_packet)

      # Find existing NAT mapping
      external_tuple = extract_external_tuple(ipv4_packet, transport_packet)
      mapping = lookup_external_mapping(external_tuple)
      return nil unless mapping

      # Rewrite destination IP and port
      original_dest_ip = ipv4_packet.destination_ip_string
      original_dest_port = get_destination_port(transport_packet)

      ipv4_packet.destination_ip = IPv4Packet.string_to_ip(mapping.internal_ip)
      set_destination_port(transport_packet, mapping.internal_port) if transport_packet

      # Recalculate checksums
      update_checksums(ipv4_packet, transport_packet)

      # Update mapping activity
      mapping.update_activity!
      @stats[:packets_dnat] += 1

      {
        action: :dnat_applied,
        mapping_id: mapping.object_id,
        original_ip: original_dest_ip,
        original_port: original_dest_port,
        internal_ip: mapping.internal_ip,
        internal_port: mapping.internal_port
      }
    end

    # Get NAT mapping for connection
    def get_mapping_for_connection(connection_tuple)
      internal_hash = hash_internal_tuple(connection_tuple)
      mapping_id = @internal_lookup[internal_hash]
      @mappings[mapping_id] if mapping_id
    end

    # Clean up expired mappings
    def cleanup_expired_mappings!
      current_time = Time.now
      expired_mappings = []

      @mappings.each do |id, mapping|
        if mapping.expired?(current_time)
          expired_mappings << id
        end
      end

      expired_mappings.each do |id|
        remove_mapping(id)
      end

      @stats[:last_cleanup] = current_time
      expired_mappings.size
    end

    # Get NAT statistics
    def nat_stats
      @stats.merge(
        active_mappings: @mappings.size,
        available_ports: @port_pool.available_count,
        port_utilization: @port_pool.utilization_percentage,
        tcp_mappings: @mappings.values.count { |m| m.protocol == :tcp },
        udp_mappings: @mappings.values.count { |m| m.protocol == :udp },
        icmp_mappings: @mappings.values.count { |m| m.protocol == :icmp }
      )
    end

    # Configure NAT timeouts
    def set_timeout(protocol, state, timeout_seconds)
      key = "#{protocol}_#{state}".to_sym
      @timeouts[key] = timeout_seconds if @timeouts.key?(key)
    end

    # Check if address is in internal network
    def internal_network?(ip_address)
      # Simple implementation - in practice would check configured internal networks
      ip_int = IPv4Packet.string_to_ip(ip_address)
      
      # RFC 1918 private networks
      private_networks = [
        [0x0a000000, 0xff000000],  # 10.0.0.0/8
        [0xac100000, 0xfff00000],  # 172.16.0.0/12
        [0xc0a80000, 0xffff0000]   # 192.168.0.0/16
      ]
      
      private_networks.any? { |network, mask| (ip_int & mask) == network }
    end

    private

    # Port pool management for NAT
    class PortPool
      def initialize(port_range)
        @port_range = port_range
        @allocated_ports = Set.new
        @next_port = port_range.first
      end

      def allocate_port
        return nil if @allocated_ports.size >= @port_range.size

        # Try to find next available port
        attempts = 0
        while attempts < @port_range.size
          port = @next_port
          @next_port += 1
          @next_port = @port_range.first if @next_port > @port_range.last
          attempts += 1

          unless @allocated_ports.include?(port)
            @allocated_ports.add(port)
            return port
          end
        end

        nil  # Port exhaustion
      end

      def release_port(port)
        @allocated_ports.delete(port)
      end

      def available_count
        @port_range.size - @allocated_ports.size
      end

      def utilization_percentage
        (@allocated_ports.size.to_f / @port_range.size) * 100
      end
    end

    # Check if packet should be NAT'd outgoing
    def should_nat_outgoing?(ipv4_packet)
      internal_network?(ipv4_packet.source_ip_string) &&
      !internal_network?(ipv4_packet.destination_ip_string)
    end

    # Check if incoming packet is for our NAT
    def nat_for_us?(ipv4_packet)
      ipv4_packet.destination_ip_string == @external_ip
    end

    # Get or create NAT mapping
    def get_or_create_mapping(ipv4_packet, transport_packet, direction)
      internal_tuple = extract_internal_tuple(ipv4_packet, transport_packet)
      existing_mapping = lookup_internal_mapping(internal_tuple)
      
      return existing_mapping if existing_mapping

      # Create new mapping
      create_new_mapping(internal_tuple, transport_packet)
    end

    # Create new NAT mapping
    def create_new_mapping(internal_tuple, transport_packet)
      # Allocate external port
      external_port = @port_pool.allocate_port
      unless external_port
        @stats[:port_exhaustion] += 1
        return nil
      end

      # Determine timeout based on protocol and state
      timeout = determine_mapping_timeout(internal_tuple[:protocol], transport_packet)

      # Create mapping
      mapping = NatMapping.new(
        internal_tuple[:ip],
        internal_tuple[:port],
        @external_ip,
        external_port,
        internal_tuple[:protocol],
        Time.now,
        Time.now,
        generate_connection_id(internal_tuple),
        timeout
      )

      # Store mapping in lookup tables
      mapping_id = mapping.object_id
      @mappings[mapping_id] = mapping
      @internal_lookup[hash_internal_tuple(internal_tuple)] = mapping_id
      @external_lookup[hash_external_tuple(mapping.external_tuple)] = mapping_id

      @stats[:mappings_created] += 1
      mapping
    end

    # Remove NAT mapping
    def remove_mapping(mapping_id)
      mapping = @mappings.delete(mapping_id)
      return unless mapping

      # Clean up lookup tables
      @internal_lookup.delete(hash_internal_tuple(mapping.internal_tuple))
      @external_lookup.delete(hash_external_tuple(mapping.external_tuple))
      
      # Release port back to pool
      @port_pool.release_port(mapping.external_port)
      
      @stats[:mappings_expired] += 1
    end

    # Lookup mapping by internal tuple
    def lookup_internal_mapping(internal_tuple)
      internal_hash = hash_internal_tuple(internal_tuple)
      mapping_id = @internal_lookup[internal_hash]
      @mappings[mapping_id] if mapping_id
    end

    # Lookup mapping by external tuple
    def lookup_external_mapping(external_tuple)
      external_hash = hash_external_tuple(external_tuple)
      mapping_id = @external_lookup[external_hash]
      @mappings[mapping_id] if mapping_id
    end

    # Extract internal tuple from packet
    def extract_internal_tuple(ipv4_packet, transport_packet)
      {
        ip: ipv4_packet.source_ip_string,
        port: get_source_port(transport_packet),
        protocol: get_protocol(transport_packet)
      }
    end

    # Extract external tuple from packet
    def extract_external_tuple(ipv4_packet, transport_packet)
      {
        ip: ipv4_packet.destination_ip_string,
        port: get_destination_port(transport_packet),
        protocol: get_protocol(transport_packet)
      }
    end

    # Get source port from transport packet
    def get_source_port(transport_packet)
      case transport_packet
      when TcpSegment, UdpDatagram
        transport_packet.source_port
      else
        0  # ICMP or other protocols
      end
    end

    # Get destination port from transport packet
    def get_destination_port(transport_packet)
      case transport_packet
      when TcpSegment, UdpDatagram
        transport_packet.destination_port
      else
        0  # ICMP or other protocols
      end
    end

    # Set source port in transport packet
    def set_source_port(transport_packet, port)
      case transport_packet
      when TcpSegment, UdpDatagram
        transport_packet.source_port = port
      end
    end

    # Set destination port in transport packet
    def set_destination_port(transport_packet, port)
      case transport_packet
      when TcpSegment, UdpDatagram
        transport_packet.destination_port = port
      end
    end

    # Get protocol from transport packet
    def get_protocol(transport_packet)
      case transport_packet
      when TcpSegment then :tcp
      when UdpDatagram then :udp
      else :icmp
      end
    end

    # Update packet checksums after NAT
    def update_checksums(ipv4_packet, transport_packet)
      # Update IP checksum
      ipv4_packet.update_checksum!

      # Update transport checksum if applicable
      case transport_packet
      when TcpSegment
        transport_packet.update_checksum!(ipv4_packet.source_ip, ipv4_packet.destination_ip)
      when UdpDatagram
        transport_packet.update_checksum!(ipv4_packet.source_ip, ipv4_packet.destination_ip)
      end
    end

    # Determine mapping timeout
    def determine_mapping_timeout(protocol, transport_packet)
      case protocol
      when :tcp
        if transport_packet.is_a?(TcpSegment)
          if transport_packet.syn? && !transport_packet.ack?
            @timeouts[:tcp_syn_sent]
          elsif transport_packet.fin?
            @timeouts[:tcp_fin_wait]
          else
            @timeouts[:tcp_established]
          end
        else
          @timeouts[:tcp_established]
        end
      when :udp
        @timeouts[:udp_active]
      else
        @timeouts[:icmp]
      end
    end

    # Hash internal tuple for lookup
    def hash_internal_tuple(tuple)
      "#{tuple[:ip]}:#{tuple[:port]}/#{tuple[:protocol]}"
    end

    # Hash external tuple for lookup
    def hash_external_tuple(tuple)
      "#{tuple[:ip]}:#{tuple[:port]}/#{tuple[:protocol]}"
    end

    # Generate connection ID
    def generate_connection_id(tuple)
      "#{tuple[:ip]}:#{tuple[:port]}/#{tuple[:protocol]}"
    end
  end
end
# frozen_string_literal: true

module AetherPacket
  # NetworkAppliance integrates all NAT components into a complete router
  # Provides enterprise-grade NAT, connection tracking, and packet processing
  class NetworkAppliance
    attr_reader :interfaces, :nat_engine, :packet_forwarder, :arp_protocol, :routing_table, :stats

    def initialize(external_ip:, internal_networks:)
      @external_ip = external_ip
      @internal_networks = internal_networks
      
      # Core components
      @routing_table = RoutingTable.new
      @arp_protocol = ArpProtocol.new
      @nat_engine = StatefulNatEngine.new(
        external_ip: external_ip,
        internal_networks: internal_networks
      )
      @packet_forwarder = PacketForwarder.new(
        routing_table: @routing_table,
        arp_protocol: @arp_protocol
      )
      
      # Network interfaces
      @interfaces = {}
      @reactor = nil
      
      # Processing statistics
      @stats = {
        packets_processed: 0,
        packets_forwarded: 0,
        packets_nat: 0,
        packets_dropped: 0,
        processing_errors: 0,
        last_reset: Time.now
      }
    end

    # Add network interface to appliance
    def add_interface(name, interface_name, ip_address, mac_address, is_external: false)
      network_interface = NetworkInterface.new(interface_name)
      network_interface.enable_promiscuous!
      
      @interfaces[name] = {
        interface: network_interface,
        interface_name: interface_name,
        ip_address: ip_address,
        mac_address: mac_address,
        is_external: is_external,
        packets_received: 0,
        packets_sent: 0
      }
      
      # Add interface to packet forwarder
      @packet_forwarder.add_interface(name, network_interface, mac_address)
      
      # Add virtual IP to ARP protocol
      @arp_protocol.add_virtual_ip(ip_address, mac_address)
      
      network_interface
    end

    # Start the network appliance
    def start
      return false if @reactor
      
      @reactor = PacketReactor.new
      
      # Add interfaces to reactor
      @interfaces.each do |name, interface_info|
        @reactor.add_interface(interface_info[:interface_name])
      end
      
      # Register packet processing callback
      @reactor.on_packet do |interface_name, raw_packet_data, timestamp|
        process_packet(interface_name, raw_packet_data, timestamp)
      end
      
      # Register error callback
      @reactor.on_error do |error, context|
        handle_processing_error(error, context)
      end
      
      # Start packet processing
      Thread.new { @reactor.start }
    end

    # Stop the network appliance
    def stop
      @reactor&.stop
      @reactor = nil
    end

    # Add routing rule
    def add_route(network, prefix_length, gateway: nil, interface:, metric: 0)
      @routing_table.add_route(network, prefix_length, gateway: gateway, interface: interface, metric: metric)
    end

    # Add NAT port forwarding rule
    def add_port_forwarding(external_port:, internal_ip:, internal_port:, protocol: :tcp)
      @nat_engine.add_port_forwarding(
        external_port: external_port,
        internal_ip: internal_ip,
        internal_port: internal_port,
        protocol: protocol
      )
    end

    # Get appliance statistics
    def appliance_stats
      nat_stats = @nat_engine.nat_statistics
      routing_stats = @routing_table.stats
      forwarding_stats = @packet_forwarder.forwarding_stats
      
      interface_stats = {}
      @interfaces.each do |name, info|
        interface_stats[name] = {
          packets_received: info[:packets_received],
          packets_sent: info[:packets_sent],
          ip_address: info[:ip_address],
          mac_address: info[:mac_address],
          is_external: info[:is_external]
        }
      end
      
      @stats.merge(
        nat_stats: nat_stats,
        routing_stats: routing_stats,
        forwarding_stats: forwarding_stats,
        interface_stats: interface_stats,
        reactor_stats: @reactor&.performance_stats
      )
    end

    # Get active connections
    def active_connections
      @nat_engine.active_nat_sessions
    end

    # Cleanup expired connections and mappings
    def cleanup!
      @nat_engine.cleanup!
      @routing_table.stats  # Refresh routing stats
    end

    private

    # Main packet processing pipeline
    def process_packet(interface_name, raw_packet_data, timestamp)
      @stats[:packets_processed] += 1
      
      begin
        # Find interface info
        interface_info = find_interface_by_name(interface_name)
        unless interface_info
          @stats[:packets_dropped] += 1
          return
        end
        
        # Parse Ethernet frame
        ethernet_frame = EthernetFrame.parse(raw_packet_data)
        
        # Process based on frame type
        case ethernet_frame.frame_type
        when :ipv4
          process_ipv4_packet(ethernet_frame, interface_info, timestamp)
        when :arp
          process_arp_packet(ethernet_frame, interface_info, timestamp)
        else
          @stats[:packets_dropped] += 1
        end
        
      rescue MalformedPacketError, ChecksumError => e
        @stats[:packets_dropped] += 1
        handle_processing_error(e, interface: interface_name, packet_type: :malformed)
      rescue => e
        @stats[:processing_errors] += 1
        handle_processing_error(e, interface: interface_name, packet_type: :unknown)
      end
    end

    # Process IPv4 packets
    def process_ipv4_packet(ethernet_frame, interface_info, timestamp)
      ipv4_packet = IPv4Packet.parse(ethernet_frame.payload)
      
      # Parse transport layer
      transport_packet = parse_transport_packet(ipv4_packet)
      
      # Determine packet direction
      direction = determine_packet_direction(ipv4_packet, interface_info)
      
      case direction
      when :outbound
        process_outbound_packet(ethernet_frame, ipv4_packet, transport_packet, interface_info)
      when :inbound
        process_inbound_packet(ethernet_frame, ipv4_packet, transport_packet, interface_info)
      when :local
        process_local_packet(ethernet_frame, ipv4_packet, transport_packet, interface_info)
      else
        @stats[:packets_dropped] += 1
      end
    end

    # Process ARP packets
    def process_arp_packet(ethernet_frame, interface_info, timestamp)
      arp_packet = ArpPacket.parse(ethernet_frame.payload)
      
      response_data = @arp_protocol.process_packet(arp_packet, interface_info)
      
      if response_data
        interface_info[:interface].write_packet(response_data)
        interface_info[:packets_sent] += 1
      end
    end

    # Process outbound packets (internal -> external)
    def process_outbound_packet(ethernet_frame, ipv4_packet, transport_packet, interface_info)
      # Apply NAT if needed
      nat_result = @nat_engine.process_outbound_packet(ethernet_frame, ipv4_packet, transport_packet)
      
      if nat_result
        # Send NAT'd packet
        forward_packet_to_external(nat_result, interface_info)
        @stats[:packets_nat] += 1
      else
        # Forward without NAT
        forwarding_result = @packet_forwarder.forward_packet(ipv4_packet, interface_info[:name])
        
        if forwarding_result && forwarding_result[:action] == :forwarded
          @stats[:packets_forwarded] += 1
        else
          @stats[:packets_dropped] += 1
        end
      end
    end

    # Process inbound packets (external -> internal)
    def process_inbound_packet(ethernet_frame, ipv4_packet, transport_packet, interface_info)
      # Try NAT first (DNAT/port forwarding)
      nat_result = @nat_engine.process_inbound_packet(ethernet_frame, ipv4_packet, transport_packet)
      
      if nat_result
        # Send NAT'd packet to internal network
        forward_packet_to_internal(nat_result, ipv4_packet)
        @stats[:packets_nat] += 1
      else
        # Check if packet is for us (router management, etc.)
        if packet_for_router?(ipv4_packet, interface_info)
          process_router_packet(ipv4_packet, transport_packet, interface_info)
        else
          @stats[:packets_dropped] += 1
        end
      end
    end

    # Process local delivery packets
    def process_local_packet(ethernet_frame, ipv4_packet, transport_packet, interface_info)
      case ipv4_packet.protocol
      when IPv4Packet::PROTO_ICMP
        process_icmp_for_router(ipv4_packet, transport_packet, interface_info)
      else
        # Other protocols for router management would go here
        @stats[:packets_dropped] += 1
      end
    end

    # Parse transport layer packet
    def parse_transport_packet(ipv4_packet)
      case ipv4_packet.protocol
      when IPv4Packet::PROTO_TCP
        TcpSegment.parse(ipv4_packet.payload)
      when IPv4Packet::PROTO_UDP
        UdpDatagram.parse(ipv4_packet.payload)
      when IPv4Packet::PROTO_ICMP
        IcmpPacket.parse(ipv4_packet.payload)
      else
        nil
      end
    end

    # Determine packet direction
    def determine_packet_direction(ipv4_packet, interface_info)
      source_ip = ipv4_packet.source_ip_string
      dest_ip = ipv4_packet.destination_ip_string
      
      source_internal = internal_network?(source_ip)
      dest_internal = internal_network?(dest_ip)
      dest_for_router = router_ip?(dest_ip)
      
      if dest_for_router
        :local
      elsif source_internal && !dest_internal
        :outbound
      elsif !source_internal && dest_internal
        :inbound
      elsif source_internal && dest_internal
        :internal_forwarding
      else
        :transit  # External to external (should be dropped)
      end
    end

    # Check if IP is in internal networks
    def internal_network?(ip_address)
      return false unless ip_address
      
      @internal_networks.any? do |network, prefix_length|
        route = RoutingTable::Route.new(network, prefix_length, nil, nil, 0, Time.now)
        route.contains_ip?(ip_address)
      end
    end

    # Check if IP belongs to router
    def router_ip?(ip_address)
      @interfaces.values.any? { |info| info[:ip_address] == ip_address } ||
      ip_address == @external_ip
    end

    # Check if packet is for router
    def packet_for_router?(ipv4_packet, interface_info)
      router_ip?(ipv4_packet.destination_ip_string)
    end

    # Process ICMP packets destined for router
    def process_icmp_for_router(ipv4_packet, icmp_packet, interface_info)
      icmp_protocol = IcmpProtocol.new
      
      response = icmp_protocol.process_packet(
        icmp_packet,
        ipv4_packet.source_ip_string,
        ipv4_packet.destination_ip_string,
        interface_info
      )
      
      if response && response[:frame_data]
        interface_info[:interface].write_packet(response[:frame_data])
        interface_info[:packets_sent] += 1
      end
    end

    # Forward packet to external interface
    def forward_packet_to_external(packet_data, source_interface_info)
      external_interface = find_external_interface
      return unless external_interface
      
      external_interface[:interface].write_packet(packet_data)
      external_interface[:packets_sent] += 1
    end

    # Forward packet to internal network
    def forward_packet_to_internal(packet_data, ipv4_packet)
      # Use routing table to determine output interface
      route = @routing_table.lookup(ipv4_packet.destination_ip_string)
      return unless route
      
      output_interface = @interfaces[route.interface]
      return unless output_interface
      
      output_interface[:interface].write_packet(packet_data)
      output_interface[:packets_sent] += 1
    end

    # Find interface by name
    def find_interface_by_name(interface_name)
      @interfaces.values.find { |info| info[:interface_name] == interface_name }
    end

    # Find external interface
    def find_external_interface
      @interfaces.values.find { |info| info[:is_external] }
    end

    # Handle processing errors
    def handle_processing_error(error, context)
      # Log error (in production, would use proper logging)
      puts "Processing error: #{error.class}: #{error.message} - Context: #{context}"
    end

    # Process router management packets
    def process_router_packet(ipv4_packet, transport_packet, interface_info)
      # Handle management protocols like SNMP, HTTP management, etc.
      # For now, just drop
      @stats[:packets_dropped] += 1
    end
  end
end
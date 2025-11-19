# frozen_string_literal: true

module AetherPacket
  # PacketForwarder implements Layer 3 IP packet forwarding
  # Handles TTL decrement, checksum recalculation, and interface routing
  class PacketForwarder
    attr_reader :routing_table, :arp_protocol, :interfaces, :stats

    def initialize(routing_table:, arp_protocol:)
      @routing_table = routing_table
      @arp_protocol = arp_protocol
      @interfaces = {}
      
      # Forwarding statistics
      @stats = {
        packets_forwarded: 0,
        packets_dropped: 0,
        ttl_expired: 0,
        no_route: 0,
        arp_failures: 0,
        checksum_errors: 0,
        last_reset: Time.now
      }
    end

    # Register network interface for forwarding
    def add_interface(name, interface, mac_address)
      @interfaces[name] = {
        interface: interface,
        mac_address: mac_address
      }
    end

    # Remove network interface
    def remove_interface(name)
      @interfaces.delete(name)
    end

    # Forward IPv4 packet to appropriate interface
    def forward_packet(ipv4_packet, source_interface = nil)
      begin
        # Validate packet before forwarding
        validate_packet(ipv4_packet)
        
        # Find route for destination
        route = @routing_table.lookup(ipv4_packet.destination_ip_string)
        unless route
          @stats[:no_route] += 1
          @stats[:packets_dropped] += 1
          return create_icmp_unreachable(ipv4_packet, source_interface, :net_unreachable)
        end

        # Check if packet is destined for local interface
        if local_destination?(ipv4_packet.destination_ip_string)
          return :local_delivery
        end

        # Decrement TTL and update checksum
        ipv4_packet.decrement_ttl!
        
        # Determine next hop
        next_hop_ip = route.gateway || ipv4_packet.destination_ip_string
        
        # Resolve next hop MAC address
        next_hop_mac = @arp_protocol.lookup_mac(next_hop_ip)
        unless next_hop_mac
          @stats[:arp_failures] += 1
          @stats[:packets_dropped] += 1
          return create_arp_request(next_hop_ip, route.interface)
        end

        # Get output interface
        output_interface = @interfaces[route.interface]
        unless output_interface
          @stats[:packets_dropped] += 1
          return nil
        end

        # Create new Ethernet frame for forwarded packet
        forwarded_frame = create_forwarded_frame(
          ipv4_packet,
          output_interface[:mac_address],
          next_hop_mac
        )

        # Send packet on output interface
        output_interface[:interface].write_packet(forwarded_frame)
        
        @stats[:packets_forwarded] += 1
        
        # Return forwarding result
        {
          action: :forwarded,
          route: route,
          next_hop: next_hop_ip,
          output_interface: route.interface
        }

      rescue NetworkError => e
        handle_forwarding_error(e, ipv4_packet, source_interface)
      end
    end

    # Process incoming Ethernet frame for forwarding
    def process_frame(ethernet_frame, interface_name)
      return nil unless ethernet_frame.frame_type == :ipv4
      
      begin
        ipv4_packet = IPv4Packet.parse(ethernet_frame.payload)
        forward_packet(ipv4_packet, interface_name)
      rescue MalformedPacketError, ChecksumError => e
        @stats[:checksum_errors] += 1
        @stats[:packets_dropped] += 1
        nil
      end
    end

    # Check if IP is configured on local interfaces
    def local_destination?(ip_address)
      @arp_protocol.virtual_ips.key?(ip_address)
    end

    # Get forwarding statistics
    def forwarding_stats
      now = Time.now
      duration = now - @stats[:last_reset]
      
      @stats.merge(
        duration: duration,
        forwarding_rate: duration > 0 ? @stats[:packets_forwarded] / duration : 0,
        drop_rate: duration > 0 ? @stats[:packets_dropped] / duration : 0,
        total_processed: @stats[:packets_forwarded] + @stats[:packets_dropped]
      )
    end

    # Reset statistics
    def reset_stats!
      @stats.each_key { |key| @stats[key] = 0 unless key == :last_reset }
      @stats[:last_reset] = Time.now
    end

    private

    # Validate packet before forwarding
    def validate_packet(ipv4_packet)
      raise NetworkError, "TTL expired" if ipv4_packet.ttl <= 1
      raise NetworkError, "Invalid destination" if ipv4_packet.destination_ip == 0
      raise NetworkError, "Fragmented packets not supported" if ipv4_packet.fragmented?
    end

    # Create Ethernet frame for forwarded packet
    def create_forwarded_frame(ipv4_packet, source_mac, destination_mac)
      EthernetFrame.create(
        destination_mac: destination_mac,
        source_mac: source_mac,
        ethertype: EthernetFrame::ETHERTYPE_IPv4,
        payload: ipv4_packet.to_binary_s
      ).to_binary_s
    end

    # Create ARP request for unknown next hop
    def create_arp_request(target_ip, interface_name)
      interface_info = @interfaces[interface_name]
      return nil unless interface_info

      # Find our IP on this interface
      our_ip = find_interface_ip(interface_name)
      return nil unless our_ip

      arp_request = @arp_protocol.create_request(
        target_ip,
        interface_info[:mac_address],
        our_ip
      )

      interface_info[:interface].write_packet(arp_request)
      
      {
        action: :arp_request_sent,
        target_ip: target_ip,
        interface: interface_name
      }
    end

    # Create ICMP Destination Unreachable message
    def create_icmp_unreachable(original_packet, source_interface, reason)
      return nil unless source_interface && @interfaces[source_interface]
      
      # Get our IP on source interface
      our_ip = find_interface_ip(source_interface)
      return nil unless our_ip

      # Create ICMP packet (simplified)
      icmp_type = case reason
      when :net_unreachable then 3
      when :host_unreachable then 1
      when :port_unreachable then 3
      else 3
      end

      icmp_code = case reason
      when :net_unreachable then 0
      when :host_unreachable then 1
      when :port_unreachable then 3
      else 0
      end

      # ICMP header + original IP header + 8 bytes of data
      icmp_payload = [
        icmp_type, icmp_code, 0, 0,  # Type, Code, Checksum (0 for now), Unused
        0, 0, 0, 0                    # Unused padding
      ].pack("C4N") + original_packet.to_binary_s[0, 28]

      # Calculate ICMP checksum
      checksum = calculate_icmp_checksum(icmp_payload)
      icmp_payload[2, 2] = [checksum].pack("n")

      # Create ICMP reply packet
      icmp_packet = IPv4Packet.create(
        source_ip: our_ip,
        destination_ip: original_packet.source_ip_string,
        protocol: IPv4Packet::PROTO_ICMP,
        payload: icmp_payload
      )

      # Look up source MAC for reply
      source_mac = @arp_protocol.lookup_mac(original_packet.source_ip_string)
      return nil unless source_mac

      interface_info = @interfaces[source_interface]
      
      icmp_frame = EthernetFrame.create(
        destination_mac: source_mac,
        source_mac: interface_info[:mac_address],
        ethertype: EthernetFrame::ETHERTYPE_IPv4,
        payload: icmp_packet.to_binary_s
      )

      interface_info[:interface].write_packet(icmp_frame.to_binary_s)
      
      {
        action: :icmp_sent,
        type: reason,
        destination: original_packet.source_ip_string
      }
    end

    # Handle forwarding errors
    def handle_forwarding_error(error, packet, source_interface)
      case error.message
      when /TTL expired/
        @stats[:ttl_expired] += 1
        @stats[:packets_dropped] += 1
        create_icmp_unreachable(packet, source_interface, :ttl_expired)
      else
        @stats[:packets_dropped] += 1
        nil
      end
    end

    # Find our IP address on given interface
    def find_interface_ip(interface_name)
      # Look for virtual IPs assigned to this interface
      @arp_protocol.virtual_ips.each do |ip, info|
        return ip if info[:interface] == interface_name
      end
      nil
    end

    # Calculate ICMP checksum
    def calculate_icmp_checksum(data)
      # Pad data to even length
      data += "\x00" if data.length.odd?
      
      # Calculate checksum over 16-bit words
      sum = data.unpack("n*").sum
      
      # Add carry bits
      while (sum >> 16) > 0
        sum = (sum & 0xffff) + (sum >> 16)
      end
      
      # Return one's complement
      ~sum & 0xffff
    end
  end
end
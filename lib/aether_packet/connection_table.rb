# frozen_string_literal: true

module AetherPacket
  # ConnectionTable implements stateful connection tracking (conntrack)
  # Maintains active flow state for TCP/UDP connections through the router
  class ConnectionTable
    # Connection states for TCP
    TCP_NEW = :new
    TCP_ESTABLISHED = :established
    TCP_FIN_WAIT = :fin_wait
    TCP_CLOSE_WAIT = :close_wait
    TCP_CLOSING = :closing
    TCP_LAST_ACK = :last_ack
    TCP_TIME_WAIT = :time_wait
    TCP_CLOSED = :closed

    # Connection states for UDP (simplified)
    UDP_NEW = :new
    UDP_ESTABLISHED = :established
    UDP_TIMEOUT = :timeout

    # Connection entry structure
    Connection = Struct.new(
      :id, :protocol, :state, :created_at, :last_seen, :timeout,
      :source_ip, :source_port, :destination_ip, :destination_port,
      :bytes_sent, :bytes_received, :packets_sent, :packets_received,
      :tcp_state_machine, :nat_mapping, :metadata
    ) do
      def expired?(current_time = Time.now)
        current_time - last_seen > timeout
      end

      def update_activity!(bytes = 0, direction = :outbound)
        self.last_seen = Time.now
        
        if direction == :outbound
          self.bytes_sent += bytes
          self.packets_sent += 1
        else
          self.bytes_received += bytes
          self.packets_received += 1
        end
      end

      def total_bytes
        bytes_sent + bytes_received
      end

      def total_packets
        packets_sent + packets_received
      end

      def connection_tuple
        {
          protocol: protocol,
          source_ip: source_ip,
          source_port: source_port,
          destination_ip: destination_ip,
          destination_port: destination_port
        }
      end

      def reverse_tuple
        {
          protocol: protocol,
          source_ip: destination_ip,
          source_port: destination_port,
          destination_ip: source_ip,
          destination_port: source_port
        }
      end
    end

    # TCP state machine for connection tracking
    class TcpStateMachine
      attr_reader :state, :client_sequence, :server_sequence

      def initialize
        @state = TCP_NEW
        @client_sequence = nil
        @server_sequence = nil
        @client_fin_seq = nil
        @server_fin_seq = nil
      end

      # Process TCP segment and update state
      def process_segment(tcp_segment, direction)
        case @state
        when TCP_NEW
          process_new_state(tcp_segment, direction)
        when TCP_ESTABLISHED
          process_established_state(tcp_segment, direction)
        when TCP_FIN_WAIT, TCP_CLOSE_WAIT, TCP_CLOSING, TCP_LAST_ACK
          process_closing_state(tcp_segment, direction)
        when TCP_TIME_WAIT
          process_time_wait_state(tcp_segment, direction)
        end

        @state
      end

      private

      def process_new_state(tcp_segment, direction)
        if tcp_segment.syn? && !tcp_segment.ack?
          # Initial SYN
          @client_sequence = tcp_segment.sequence_number
          @state = :syn_sent
        elsif tcp_segment.syn? && tcp_segment.ack?
          # SYN-ACK response
          @server_sequence = tcp_segment.sequence_number
          @state = :syn_received
        elsif tcp_segment.ack? && !tcp_segment.syn?
          # Final ACK of 3-way handshake
          @state = TCP_ESTABLISHED
        elsif tcp_segment.rst?
          @state = TCP_CLOSED
        end
      end

      def process_established_state(tcp_segment, direction)
        if tcp_segment.fin?
          @state = TCP_FIN_WAIT
          if direction == :outbound
            @client_fin_seq = tcp_segment.sequence_number
          else
            @server_fin_seq = tcp_segment.sequence_number
          end
        elsif tcp_segment.rst?
          @state = TCP_CLOSED
        end
      end

      def process_closing_state(tcp_segment, direction)
        if tcp_segment.fin?
          if @state == TCP_FIN_WAIT
            @state = TCP_CLOSING
          end
          
          if direction == :outbound
            @client_fin_seq = tcp_segment.sequence_number
          else
            @server_fin_seq = tcp_segment.sequence_number
          end
        elsif tcp_segment.ack?
          # ACK of FIN
          if @client_fin_seq && @server_fin_seq
            @state = TCP_TIME_WAIT
          elsif @state == TCP_FIN_WAIT
            @state = TCP_CLOSE_WAIT
          end
        elsif tcp_segment.rst?
          @state = TCP_CLOSED
        end
      end

      def process_time_wait_state(tcp_segment, direction)
        # Stay in TIME_WAIT, will timeout naturally
        @state = TCP_CLOSED if tcp_segment.rst?
      end
    end

    attr_reader :connections, :stats

    def initialize
      @connections = {}  # connection_id -> Connection
      @reverse_lookup = {}  # reverse_tuple_hash -> connection_id
      @cleanup_interval = 60  # Cleanup every 60 seconds
      @last_cleanup = Time.now
      
      # Default timeouts (seconds)
      @timeouts = {
        tcp_established: 3600,    # 1 hour
        tcp_syn_sent: 120,        # 2 minutes
        tcp_syn_received: 60,     # 1 minute
        tcp_fin_wait: 120,        # 2 minutes
        tcp_time_wait: 60,        # 1 minute
        tcp_closed: 10,           # 10 seconds
        udp_established: 300,     # 5 minutes
        udp_new: 30,              # 30 seconds
        icmp: 30                  # 30 seconds
      }

      @stats = {
        connections_created: 0,
        connections_closed: 0,
        connections_expired: 0,
        connections_active: 0,
        bytes_tracked: 0,
        packets_tracked: 0,
        last_cleanup: @last_cleanup
      }
    end

    # Track new or existing connection
    def track_connection(ip_packet, transport_packet)
      tuple = extract_connection_tuple(ip_packet, transport_packet)
      return nil unless tuple

      connection_id = generate_connection_id(tuple)
      connection = @connections[connection_id]

      if connection
        # Update existing connection
        update_existing_connection(connection, ip_packet, transport_packet)
      else
        # Create new connection
        connection = create_new_connection(tuple, ip_packet, transport_packet)
        @connections[connection_id] = connection
        @reverse_lookup[hash_tuple(connection.reverse_tuple)] = connection_id
        @stats[:connections_created] += 1
      end

      # Periodic cleanup
      cleanup_expired_connections if should_cleanup?

      connection
    end

    # Lookup connection by tuple
    def lookup_connection(tuple)
      connection_id = generate_connection_id(tuple)
      @connections[connection_id] || lookup_reverse_connection(tuple)
    end

    # Get all active connections
    def active_connections
      @connections.values.reject(&:expired?)
    end

    # Get connections by protocol
    def connections_by_protocol(protocol)
      @connections.values.select { |conn| conn.protocol == protocol }
    end

    # Get connection statistics
    def connection_stats
      active = active_connections
      
      @stats.merge(
        connections_active: active.size,
        tcp_connections: active.count { |c| c.protocol == :tcp },
        udp_connections: active.count { |c| c.protocol == :udp },
        icmp_connections: active.count { |c| c.protocol == :icmp },
        established_tcp: active.count { |c| c.protocol == :tcp && c.state == TCP_ESTABLISHED },
        total_bytes: active.sum(&:total_bytes),
        total_packets: active.sum(&:total_packets)
      )
    end

    # Force cleanup of expired connections
    def cleanup_expired_connections!
      cleanup_expired_connections(force: true)
    end

    # Clear all connections
    def clear_all_connections!
      @connections.clear
      @reverse_lookup.clear
      @stats[:connections_closed] += @stats[:connections_active]
      @stats[:connections_active] = 0
    end

    private

    # Extract connection tuple from packets
    def extract_connection_tuple(ip_packet, transport_packet)
      case transport_packet
      when TcpSegment, UdpDatagram
        {
          protocol: transport_packet.is_a?(TcpSegment) ? :tcp : :udp,
          source_ip: ip_packet.source_ip_string,
          source_port: transport_packet.source_port,
          destination_ip: ip_packet.destination_ip_string,
          destination_port: transport_packet.destination_port
        }
      else
        # For ICMP or other protocols
        {
          protocol: :icmp,
          source_ip: ip_packet.source_ip_string,
          source_port: 0,
          destination_ip: ip_packet.destination_ip_string,
          destination_port: 0
        }
      end
    end

    # Generate consistent connection ID
    def generate_connection_id(tuple)
      # Create consistent ID regardless of direction
      if tuple[:source_ip] < tuple[:destination_ip] || 
         (tuple[:source_ip] == tuple[:destination_ip] && tuple[:source_port] < tuple[:destination_port])
        "#{tuple[:source_ip]}:#{tuple[:source_port]}-#{tuple[:destination_ip]}:#{tuple[:destination_port]}/#{tuple[:protocol]}"
      else
        "#{tuple[:destination_ip]}:#{tuple[:destination_port]}-#{tuple[:source_ip]}:#{tuple[:source_port]}/#{tuple[:protocol]}"
      end
    end

    # Hash tuple for reverse lookup
    def hash_tuple(tuple)
      "#{tuple[:source_ip]}:#{tuple[:source_port]}-#{tuple[:destination_ip]}:#{tuple[:destination_port]}/#{tuple[:protocol]}"
    end

    # Create new connection entry
    def create_new_connection(tuple, ip_packet, transport_packet)
      timeout = determine_timeout(tuple[:protocol], transport_packet)
      
      connection = Connection.new(
        generate_connection_id(tuple),
        tuple[:protocol],
        determine_initial_state(transport_packet),
        Time.now,
        Time.now,
        timeout,
        tuple[:source_ip],
        tuple[:source_port],
        tuple[:destination_ip],
        tuple[:destination_port],
        ip_packet.total_length,  # bytes_sent
        0,                       # bytes_received
        1,                       # packets_sent
        0,                       # packets_received
        tuple[:protocol] == :tcp ? TcpStateMachine.new : nil,
        nil,                     # nat_mapping
        {}                       # metadata
      )

      # Process initial packet for TCP state machine
      if connection.tcp_state_machine && transport_packet.is_a?(TcpSegment)
        connection.tcp_state_machine.process_segment(transport_packet, :outbound)
        connection.state = connection.tcp_state_machine.state
      end

      connection
    end

    # Update existing connection
    def update_existing_connection(connection, ip_packet, transport_packet)
      # Determine direction
      tuple = extract_connection_tuple(ip_packet, transport_packet)
      original_tuple = connection.connection_tuple
      
      direction = if tuple[:source_ip] == original_tuple[:source_ip] && 
                     tuple[:source_port] == original_tuple[:source_port]
                    :outbound
                  else
                    :inbound
                  end

      # Update activity
      connection.update_activity!(ip_packet.total_length, direction)

      # Update TCP state machine
      if connection.tcp_state_machine && transport_packet.is_a?(TcpSegment)
        connection.tcp_state_machine.process_segment(transport_packet, direction)
        connection.state = connection.tcp_state_machine.state
      end

      # Update timeout based on current state
      connection.timeout = determine_timeout(connection.protocol, transport_packet, connection.state)
    end

    # Lookup connection in reverse direction
    def lookup_reverse_connection(tuple)
      reverse_hash = hash_tuple({
        protocol: tuple[:protocol],
        source_ip: tuple[:destination_ip],
        source_port: tuple[:destination_port],
        destination_ip: tuple[:source_ip],
        destination_port: tuple[:source_port]
      })
      
      connection_id = @reverse_lookup[reverse_hash]
      @connections[connection_id] if connection_id
    end

    # Determine initial connection state
    def determine_initial_state(transport_packet)
      case transport_packet
      when TcpSegment
        if transport_packet.syn? && !transport_packet.ack?
          :syn_sent
        elsif transport_packet.syn? && transport_packet.ack?
          :syn_received
        else
          TCP_NEW
        end
      when UdpDatagram
        UDP_NEW
      else
        :new
      end
    end

    # Determine connection timeout
    def determine_timeout(protocol, transport_packet, current_state = nil)
      case protocol
      when :tcp
        case current_state || determine_initial_state(transport_packet)
        when TCP_ESTABLISHED then @timeouts[:tcp_established]
        when :syn_sent then @timeouts[:tcp_syn_sent]
        when :syn_received then @timeouts[:tcp_syn_received]
        when TCP_FIN_WAIT, TCP_CLOSE_WAIT, TCP_CLOSING, TCP_LAST_ACK then @timeouts[:tcp_fin_wait]
        when TCP_TIME_WAIT then @timeouts[:tcp_time_wait]
        when TCP_CLOSED then @timeouts[:tcp_closed]
        else @timeouts[:tcp_established]
        end
      when :udp
        current_state == UDP_ESTABLISHED ? @timeouts[:udp_established] : @timeouts[:udp_new]
      else
        @timeouts[:icmp]
      end
    end

    # Check if cleanup should run
    def should_cleanup?
      Time.now - @last_cleanup > @cleanup_interval
    end

    # Cleanup expired connections
    def cleanup_expired_connections(force: false)
      return unless force || should_cleanup?

      expired_ids = []
      current_time = Time.now

      @connections.each do |id, connection|
        if connection.expired?(current_time)
          expired_ids << id
        end
      end

      expired_ids.each do |id|
        connection = @connections.delete(id)
        @reverse_lookup.delete(hash_tuple(connection.reverse_tuple)) if connection
        @stats[:connections_expired] += 1
        @stats[:connections_closed] += 1
      end

      @last_cleanup = current_time
      @stats[:last_cleanup] = current_time
    end
  end
end
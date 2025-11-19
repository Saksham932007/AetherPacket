# frozen_string_literal: true

module AetherPacket
  # TcpStateTracker provides enhanced TCP state tracking and analysis
  # Implements RFC 793 state machine with security-focused extensions
  class TcpStateTracker
    # Enhanced TCP connection states
    STATE_LISTEN = :listen
    STATE_SYN_SENT = :syn_sent
    STATE_SYN_RECEIVED = :syn_received
    STATE_ESTABLISHED = :established
    STATE_FIN_WAIT_1 = :fin_wait_1
    STATE_FIN_WAIT_2 = :fin_wait_2
    STATE_CLOSE_WAIT = :close_wait
    STATE_CLOSING = :closing
    STATE_LAST_ACK = :last_ack
    STATE_TIME_WAIT = :time_wait
    STATE_CLOSED = :closed

    # Security states for anomaly detection
    STATE_INVALID = :invalid
    STATE_SUSPICIOUS = :suspicious

    # Connection tracking data
    StateInfo = Struct.new(
      :state, :client_seq, :server_seq, :client_seq_next, :server_seq_next,
      :client_window, :server_window, :created_at, :last_activity,
      :handshake_complete, :closing_initiated_by, :flags_seen, :anomalies
    ) do
      def initialize(*)
        super
        self.flags_seen = Set.new
        self.anomalies = []
      end

      def record_flag(flag)
        self.flags_seen.add(flag)
      end

      def record_anomaly(type, description)
        self.anomalies << {
          type: type,
          description: description,
          timestamp: Time.now
        }
      end

      def suspicious?
        !anomalies.empty?
      end
    end

    attr_reader :connections, :stats

    def initialize
      @connections = {}
      @stats = {
        connections_tracked: 0,
        handshakes_completed: 0,
        connections_closed: 0,
        anomalies_detected: 0,
        syn_flood_detected: 0,
        last_reset: Time.now
      }
    end

    # Process TCP segment and update connection state
    def process_tcp_segment(tcp_segment, ip_packet, direction = :outbound)
      tuple = extract_connection_tuple(tcp_segment, ip_packet)
      connection_id = generate_connection_id(tuple)
      
      state_info = @connections[connection_id] || create_new_connection(connection_id, tuple)
      
      # Process segment and update state
      previous_state = state_info.state
      new_state = process_state_transition(state_info, tcp_segment, direction)
      
      # Update connection information
      update_connection_info(state_info, tcp_segment, direction)
      
      # Detect anomalies
      detect_anomalies(state_info, tcp_segment, previous_state, new_state)
      
      state_info.state = new_state
      state_info.last_activity = Time.now
      
      @connections[connection_id] = state_info
      
      {
        connection_id: connection_id,
        previous_state: previous_state,
        current_state: new_state,
        anomalies: state_info.anomalies.size,
        suspicious: state_info.suspicious?
      }
    end

    # Get connection state information
    def get_connection_state(tcp_segment, ip_packet)
      tuple = extract_connection_tuple(tcp_segment, ip_packet)
      connection_id = generate_connection_id(tuple)
      @connections[connection_id]
    end

    # Check if connection is established
    def connection_established?(connection_id)
      state_info = @connections[connection_id]
      state_info&.state == STATE_ESTABLISHED && state_info&.handshake_complete
    end

    # Check if connection is dead (closed or expired)
    def connection_dead?(connection_id, timeout = 300)
      state_info = @connections[connection_id]
      return true unless state_info
      
      return true if [STATE_CLOSED, STATE_TIME_WAIT].include?(state_info.state)
      
      # Check timeout for inactive connections
      Time.now - state_info.last_activity > timeout
    end

    # Detect potential SYN flood attacks
    def detect_syn_flood(threshold = 100, window = 60)
      current_time = Time.now
      recent_syns = @connections.values.count do |state_info|
        state_info.state == STATE_SYN_RECEIVED && 
        current_time - state_info.created_at < window
      end
      
      if recent_syns > threshold
        @stats[:syn_flood_detected] += 1
        return {
          detected: true,
          count: recent_syns,
          threshold: threshold,
          window: window
        }
      end
      
      { detected: false, count: recent_syns }
    end

    # Get connection statistics
    def connection_statistics
      active_connections = @connections.values.reject { |c| connection_dead?(c.object_id) }
      
      state_counts = Hash.new(0)
      active_connections.each { |c| state_counts[c.state] += 1 }
      
      @stats.merge(
        active_connections: active_connections.size,
        state_distribution: state_counts,
        suspicious_connections: active_connections.count(&:suspicious?),
        handshake_rate: calculate_handshake_rate,
        total_anomalies: @connections.values.sum { |c| c.anomalies.size }
      )
    end

    # Clean up old connections
    def cleanup_old_connections!(max_age = 3600)
      current_time = Time.now
      cleanup_count = 0
      
      @connections.delete_if do |id, state_info|
        should_delete = connection_dead?(id) || 
                       (current_time - state_info.created_at > max_age)
        cleanup_count += 1 if should_delete
        should_delete
      end
      
      cleanup_count
    end

    private

    # Extract connection tuple from TCP segment and IP packet
    def extract_connection_tuple(tcp_segment, ip_packet)
      {
        source_ip: ip_packet.source_ip_string,
        source_port: tcp_segment.source_port,
        destination_ip: ip_packet.destination_ip_string,
        destination_port: tcp_segment.destination_port
      }
    end

    # Generate consistent connection ID
    def generate_connection_id(tuple)
      if tuple[:source_ip] < tuple[:destination_ip] || 
         (tuple[:source_ip] == tuple[:destination_ip] && tuple[:source_port] < tuple[:destination_port])
        "#{tuple[:source_ip]}:#{tuple[:source_port]}-#{tuple[:destination_ip]}:#{tuple[:destination_port]}"
      else
        "#{tuple[:destination_ip]}:#{tuple[:destination_port]}-#{tuple[:source_ip]}:#{tuple[:source_port]}"
      end
    end

    # Create new connection tracking entry
    def create_new_connection(connection_id, tuple)
      @stats[:connections_tracked] += 1
      
      StateInfo.new(
        STATE_LISTEN,      # Initial state
        nil,               # client_seq
        nil,               # server_seq
        nil,               # client_seq_next
        nil,               # server_seq_next
        0,                 # client_window
        0,                 # server_window
        Time.now,          # created_at
        Time.now,          # last_activity
        false,             # handshake_complete
        nil,               # closing_initiated_by
        Set.new,           # flags_seen
        []                 # anomalies
      )
    end

    # Process TCP state machine transition
    def process_state_transition(state_info, tcp_segment, direction)
      current_state = state_info.state
      
      # Record flags for analysis
      tcp_segment.flag_names.each { |flag| state_info.record_flag(flag) }
      
      case current_state
      when STATE_LISTEN, STATE_CLOSED
        process_closed_state(state_info, tcp_segment, direction)
      when STATE_SYN_SENT
        process_syn_sent_state(state_info, tcp_segment, direction)
      when STATE_SYN_RECEIVED
        process_syn_received_state(state_info, tcp_segment, direction)
      when STATE_ESTABLISHED
        process_established_state(state_info, tcp_segment, direction)
      when STATE_FIN_WAIT_1
        process_fin_wait_1_state(state_info, tcp_segment, direction)
      when STATE_FIN_WAIT_2
        process_fin_wait_2_state(state_info, tcp_segment, direction)
      when STATE_CLOSE_WAIT
        process_close_wait_state(state_info, tcp_segment, direction)
      when STATE_CLOSING
        process_closing_state(state_info, tcp_segment, direction)
      when STATE_LAST_ACK
        process_last_ack_state(state_info, tcp_segment, direction)
      when STATE_TIME_WAIT
        process_time_wait_state(state_info, tcp_segment, direction)
      else
        STATE_INVALID
      end
    end

    # Process segments in CLOSED state
    def process_closed_state(state_info, tcp_segment, direction)
      if tcp_segment.syn? && !tcp_segment.ack?
        state_info.client_seq = tcp_segment.sequence_number
        state_info.client_seq_next = tcp_segment.sequence_number + 1
        STATE_SYN_SENT
      elsif tcp_segment.rst?
        STATE_CLOSED
      else
        # Unexpected segment on closed connection
        state_info.record_anomaly(:unexpected_segment, "Segment received on closed connection")
        STATE_SUSPICIOUS
      end
    end

    # Process segments in SYN_SENT state
    def process_syn_sent_state(state_info, tcp_segment, direction)
      if tcp_segment.syn? && tcp_segment.ack?
        # SYN-ACK received
        state_info.server_seq = tcp_segment.sequence_number
        state_info.server_seq_next = tcp_segment.sequence_number + 1
        STATE_SYN_RECEIVED
      elsif tcp_segment.rst?
        STATE_CLOSED
      elsif tcp_segment.syn?
        # Simultaneous open (rare but valid)
        STATE_SYN_RECEIVED
      else
        state_info.record_anomaly(:invalid_transition, "Invalid segment in SYN_SENT")
        STATE_INVALID
      end
    end

    # Process segments in SYN_RECEIVED state
    def process_syn_received_state(state_info, tcp_segment, direction)
      if tcp_segment.ack? && !tcp_segment.syn?
        # Final ACK of 3-way handshake
        state_info.handshake_complete = true
        @stats[:handshakes_completed] += 1
        STATE_ESTABLISHED
      elsif tcp_segment.rst?
        STATE_CLOSED
      else
        state_info.record_anomaly(:incomplete_handshake, "Handshake not completed properly")
        STATE_SUSPICIOUS
      end
    end

    # Process segments in ESTABLISHED state
    def process_established_state(state_info, tcp_segment, direction)
      if tcp_segment.fin?
        state_info.closing_initiated_by = direction
        STATE_FIN_WAIT_1
      elsif tcp_segment.rst?
        STATE_CLOSED
      else
        STATE_ESTABLISHED
      end
    end

    # Process segments in FIN_WAIT_1 state
    def process_fin_wait_1_state(state_info, tcp_segment, direction)
      if tcp_segment.ack?
        STATE_FIN_WAIT_2
      elsif tcp_segment.fin?
        STATE_CLOSING
      elsif tcp_segment.rst?
        STATE_CLOSED
      else
        STATE_FIN_WAIT_1
      end
    end

    # Process segments in FIN_WAIT_2 state
    def process_fin_wait_2_state(state_info, tcp_segment, direction)
      if tcp_segment.fin?
        STATE_TIME_WAIT
      elsif tcp_segment.rst?
        STATE_CLOSED
      else
        STATE_FIN_WAIT_2
      end
    end

    # Process segments in CLOSE_WAIT state
    def process_close_wait_state(state_info, tcp_segment, direction)
      if tcp_segment.fin?
        STATE_LAST_ACK
      elsif tcp_segment.rst?
        STATE_CLOSED
      else
        STATE_CLOSE_WAIT
      end
    end

    # Process segments in CLOSING state
    def process_closing_state(state_info, tcp_segment, direction)
      if tcp_segment.ack?
        STATE_TIME_WAIT
      elsif tcp_segment.rst?
        STATE_CLOSED
      else
        STATE_CLOSING
      end
    end

    # Process segments in LAST_ACK state
    def process_last_ack_state(state_info, tcp_segment, direction)
      if tcp_segment.ack?
        @stats[:connections_closed] += 1
        STATE_CLOSED
      elsif tcp_segment.rst?
        STATE_CLOSED
      else
        STATE_LAST_ACK
      end
    end

    # Process segments in TIME_WAIT state
    def process_time_wait_state(state_info, tcp_segment, direction)
      # Typically just wait for timeout, but handle resets
      if tcp_segment.rst?
        STATE_CLOSED
      else
        STATE_TIME_WAIT
      end
    end

    # Update connection information
    def update_connection_info(state_info, tcp_segment, direction)
      if direction == :outbound
        state_info.client_window = tcp_segment.window_size
        if state_info.client_seq_next
          expected_seq = state_info.client_seq_next
          if tcp_segment.sequence_number != expected_seq
            state_info.record_anomaly(:seq_mismatch, "Sequence number mismatch")
          end
        end
        state_info.client_seq_next = tcp_segment.sequence_number + tcp_segment.payload_size
        state_info.client_seq_next += 1 if tcp_segment.syn? || tcp_segment.fin?
      else
        state_info.server_window = tcp_segment.window_size
        if state_info.server_seq_next
          expected_seq = state_info.server_seq_next
          if tcp_segment.sequence_number != expected_seq
            state_info.record_anomaly(:seq_mismatch, "Sequence number mismatch")
          end
        end
        state_info.server_seq_next = tcp_segment.sequence_number + tcp_segment.payload_size
        state_info.server_seq_next += 1 if tcp_segment.syn? || tcp_segment.fin?
      end
    end

    # Detect connection anomalies
    def detect_anomalies(state_info, tcp_segment, previous_state, new_state)
      # Detect invalid flag combinations
      if tcp_segment.syn? && tcp_segment.fin?
        state_info.record_anomaly(:invalid_flags, "SYN and FIN flags both set")
        @stats[:anomalies_detected] += 1
      end

      # Detect window size anomalies
      if tcp_segment.window_size == 0 && previous_state == STATE_ESTABLISHED
        state_info.record_anomaly(:zero_window, "Zero window advertised")
      end

      # Detect potential connection hijacking
      if new_state == STATE_INVALID
        state_info.record_anomaly(:hijacking_attempt, "Possible connection hijacking")
        @stats[:anomalies_detected] += 1
      end

      # Detect RST attacks
      if tcp_segment.rst? && previous_state == STATE_ESTABLISHED
        state_info.record_anomaly(:rst_attack, "Unexpected RST in established connection")
        @stats[:anomalies_detected] += 1
      end
    end

    # Calculate handshake completion rate
    def calculate_handshake_rate
      return 0 if @stats[:connections_tracked] == 0
      (@stats[:handshakes_completed].to_f / @stats[:connections_tracked]) * 100
    end
  end
end
# frozen_string_literal: true

module AetherPacket
  # SynFloodTracker monitors SYN packet rates per source IP
  # Implements sliding window rate limiting for DDoS protection  
  class SynFloodTracker
    # Connection tracking entry for SYN flood detection
    ConnectionAttempt = Struct.new(:timestamp, :src_ip, :dst_port, :flags)

    attr_reader :syn_threshold, :time_window, :stats

    def initialize(syn_threshold: 10, time_window: 1.0, max_tracked_ips: 10000)
      @syn_threshold = syn_threshold  # Max SYNs per time window
      @time_window = time_window      # Time window in seconds
      @max_tracked_ips = max_tracked_ips
      @ip_syn_counts = {}            # IP -> [timestamp, count] pairs
      @blocked_ips = {}              # IP -> block_until timestamp  
      @connection_attempts = []       # Recent connection attempts
      @mutex = Mutex.new
      
      @stats = {
        total_syns: 0,
        blocked_syns: 0,
        unique_attackers: 0,
        flood_events: 0,
        blocked_ips_count: 0,
        peak_syn_rate: 0,
        protection_triggered: false
      }
    end

    # Track SYN packet and check for flood
    def track_syn_packet(src_ip, dst_ip, dst_port, tcp_flags)
      return :blocked if blocked_ip?(src_ip)
      
      @mutex.synchronize do
        @stats[:total_syns] += 1
        
        # Record connection attempt
        attempt = ConnectionAttempt.new(Time.now, src_ip, dst_port, tcp_flags)
        @connection_attempts << attempt
        cleanup_old_attempts
        
        # Update IP-specific SYN counting
        current_time = Time.now
        ip_data = @ip_syn_counts[src_ip] || [current_time, 0]
        
        # Reset counter if time window expired
        if current_time - ip_data[0] > @time_window
          ip_data = [current_time, 0]
        end
        
        ip_data[1] += 1
        @ip_syn_counts[src_ip] = ip_data
        
        # Update peak rate tracking
        current_rate = ip_data[1] / @time_window
        @stats[:peak_syn_rate] = [current_rate, @stats[:peak_syn_rate]].max
        
        # Check for flood threshold
        if ip_data[1] > @syn_threshold
          trigger_flood_protection(src_ip)
          @stats[:blocked_syns] += 1
          :blocked
        else
          :allowed
        end
      end
    end

    # Check if IP is currently blocked
    def blocked_ip?(src_ip)
      @mutex.synchronize do
        block_until = @blocked_ips[src_ip]
        return false unless block_until
        
        if Time.now > block_until
          # Unblock expired IP
          @blocked_ips.delete(src_ip)
          @stats[:blocked_ips_count] -= 1
          false
        else
          true
        end
      end
    end

    # Get current SYN rate for IP
    def current_syn_rate(src_ip)
      @mutex.synchronize do
        ip_data = @ip_syn_counts[src_ip]
        return 0 unless ip_data
        
        time_elapsed = Time.now - ip_data[0]
        return 0 if time_elapsed > @time_window
        
        ip_data[1] / time_elapsed
      end
    end

    # Get list of currently blocked IPs
    def blocked_ips
      @mutex.synchronize do
        current_time = Time.now
        @blocked_ips.select { |_, block_until| current_time <= block_until }.keys
      end
    end

    # Manually block IP for specified duration
    def block_ip(src_ip, duration_seconds: 60)
      @mutex.synchronize do
        @blocked_ips[src_ip] = Time.now + duration_seconds
        @stats[:blocked_ips_count] += 1
      end
    end

    # Manually unblock IP
    def unblock_ip(src_ip)
      @mutex.synchronize do
        if @blocked_ips.delete(src_ip)
          @stats[:blocked_ips_count] -= 1
          true
        else
          false
        end
      end
    end

    # Get recent connection attempts
    def recent_attempts(limit: 100)
      @mutex.synchronize { @connection_attempts.last(limit) }
    end

    # Update protection parameters
    def update_thresholds(syn_threshold: nil, time_window: nil)
      @mutex.synchronize do
        @syn_threshold = syn_threshold if syn_threshold
        @time_window = time_window if time_window
      end
    end

    # Get comprehensive protection statistics
    def protection_stats
      @mutex.synchronize do
        current_time = Time.now
        active_trackers = @ip_syn_counts.count { |_, data| current_time - data[0] <= @time_window }
        
        recent_rate = calculate_recent_syn_rate
        
        @stats.merge(
          syn_threshold: @syn_threshold,
          time_window: @time_window,
          active_ip_trackers: active_trackers,
          total_tracked_ips: @ip_syn_counts.size,
          recent_syn_rate: recent_rate,
          blocked_ips: blocked_ips.size,
          recent_attempts_count: @connection_attempts.size
        )
      end
    end

    # Reset all tracking data
    def reset!
      @mutex.synchronize do
        @ip_syn_counts.clear
        @blocked_ips.clear
        @connection_attempts.clear
        @stats.each_key { |key| @stats[key] = 0 }
        @stats[:protection_triggered] = false
      end
    end

    # Export configuration
    def export_config
      {
        syn_threshold: @syn_threshold,
        time_window: @time_window,
        max_tracked_ips: @max_tracked_ips
      }
    end

    private

    def trigger_flood_protection(src_ip)
      @stats[:flood_events] += 1
      @stats[:protection_triggered] = true
      
      # Add to unique attackers if not already tracked
      unless @blocked_ips.key?(src_ip)
        @stats[:unique_attackers] += 1
      end
      
      # Block IP for escalating duration based on repeat offenses
      base_duration = 60  # 1 minute base
      repeat_factor = [@blocked_ips[src_ip] ? 2 : 1, 8].min  # Max 8x escalation
      block_duration = base_duration * repeat_factor
      
      @blocked_ips[src_ip] = Time.now + block_duration
      @stats[:blocked_ips_count] += 1
      
      puts "SYN Flood Protection: Blocked #{src_ip} for #{block_duration}s (threshold: #{@syn_threshold})"
    end

    def cleanup_old_attempts
      cutoff_time = Time.now - (@time_window * 2)  # Keep 2x window for analysis
      @connection_attempts.select! { |attempt| attempt.timestamp > cutoff_time }
      
      # Limit memory usage
      if @connection_attempts.size > 10000
        @connection_attempts = @connection_attempts.last(5000)
      end
    end

    def calculate_recent_syn_rate
      return 0 if @connection_attempts.empty?
      
      recent_window = Time.now - @time_window
      recent_syns = @connection_attempts.count { |attempt| attempt.timestamp > recent_window }
      recent_syns / @time_window
    end

    # Cleanup expired IP tracking data
    def cleanup_expired_data
      current_time = Time.now
      
      # Remove expired IP counters
      @ip_syn_counts.delete_if { |_, data| current_time - data[0] > @time_window * 2 }
      
      # Enforce maximum tracked IPs
      if @ip_syn_counts.size > @max_tracked_ips
        # Remove oldest entries
        sorted_by_time = @ip_syn_counts.sort_by { |_, data| data[0] }
        excess_count = @ip_syn_counts.size - @max_tracked_ips
        sorted_by_time.first(excess_count).each { |ip, _| @ip_syn_counts.delete(ip) }
      end
      
      # Remove expired blocks
      @blocked_ips.delete_if { |_, block_until| current_time > block_until }
      @stats[:blocked_ips_count] = @blocked_ips.size
    end
  end

  # TcpSynProtection integrates SYN flood protection with packet processing
  # Provides enterprise-grade DDoS protection for TCP services
  class TcpSynProtection
    attr_reader :tracker, :protection_enabled, :stats

    def initialize(syn_threshold: 20, time_window: 1.0, auto_cleanup: true, **tracker_options)
      @tracker = SynFloodTracker.new(
        syn_threshold: syn_threshold,
        time_window: time_window,
        **tracker_options
      )
      @protection_enabled = true
      @auto_cleanup = auto_cleanup
      @cleanup_thread = nil
      @mutex = Mutex.new
      
      @stats = {
        packets_processed: 0,
        syn_packets_detected: 0,
        packets_blocked: 0,
        protection_events: 0,
        false_positives: 0,
        legitimate_connections: 0
      }
      
      start_cleanup_thread if @auto_cleanup
    end

    # Process TCP packet through SYN flood protection
    def process_tcp_packet(ipv4_packet, tcp_segment)
      @mutex.synchronize { @stats[:packets_processed] += 1 }
      
      return :allowed unless @protection_enabled
      
      # Check if this is a SYN packet
      if tcp_segment.syn_flag && !tcp_segment.ack_flag
        @mutex.synchronize { @stats[:syn_packets_detected] += 1 }
        
        result = @tracker.track_syn_packet(
          ipv4_packet.source_ip,
          ipv4_packet.destination_ip, 
          tcp_segment.destination_port,
          tcp_segment.flags
        )
        
        case result
        when :blocked
          @mutex.synchronize do 
            @stats[:packets_blocked] += 1 
            @stats[:protection_events] += 1
          end
          :blocked
        when :allowed
          @mutex.synchronize { @stats[:legitimate_connections] += 1 }
          :allowed
        end
      else
        # Non-SYN packets are always allowed through
        :allowed
      end
    end

    # Enable/disable SYN flood protection
    def protection_enabled=(enabled)
      @mutex.synchronize { @protection_enabled = enabled }
    end

    # Get current protection status
    def protection_status
      {
        enabled: @protection_enabled,
        syn_threshold: @tracker.syn_threshold,
        time_window: @tracker.time_window,
        blocked_ips: @tracker.blocked_ips.size,
        auto_cleanup: @auto_cleanup
      }
    end

    # Update protection thresholds
    def update_protection_config(syn_threshold: nil, time_window: nil)
      @tracker.update_thresholds(
        syn_threshold: syn_threshold,
        time_window: time_window
      )
    end

    # Manually block/unblock IPs
    def block_ip(ip, duration: 300)
      @tracker.block_ip(ip, duration_seconds: duration)
    end

    def unblock_ip(ip)
      @tracker.unblock_ip(ip)
    end

    # Get comprehensive protection statistics
    def protection_statistics
      tracker_stats = @tracker.protection_stats
      
      @mutex.synchronize do
        @stats.merge(
          tracker_stats: tracker_stats,
          protection_enabled: @protection_enabled,
          syn_block_rate: calculate_syn_block_rate,
          protection_effectiveness: calculate_protection_effectiveness
        )
      end
    end

    # Analyze recent attack patterns
    def attack_analysis
      recent_attempts = @tracker.recent_attempts(limit: 1000)
      
      # Group by source IP
      ip_attempts = recent_attempts.group_by(&:src_ip)
      
      # Analyze patterns
      attack_patterns = ip_attempts.map do |ip, attempts|
        {
          source_ip: ip,
          attempt_count: attempts.size,
          first_attempt: attempts.first.timestamp,
          last_attempt: attempts.last.timestamp,
          target_ports: attempts.map(&:dst_port).uniq,
          is_blocked: @tracker.blocked_ip?(ip),
          syn_rate: @tracker.current_syn_rate(ip)
        }
      end
      
      # Sort by attempt count (highest first)
      attack_patterns.sort_by { |pattern| -pattern[:attempt_count] }
    end

    # Stop protection and cleanup
    def shutdown!
      @mutex.synchronize { @protection_enabled = false }
      
      if @cleanup_thread
        @cleanup_thread.kill
        @cleanup_thread.join
        @cleanup_thread = nil
      end
    end

    # Reset all protection state
    def reset!
      @tracker.reset!
      @mutex.synchronize do
        @stats.each_key { |key| @stats[key] = 0 }
      end
    end

    private

    def start_cleanup_thread
      @cleanup_thread = Thread.new do
        loop do
          sleep(30)  # Cleanup every 30 seconds
          
          begin
            @tracker.send(:cleanup_expired_data)
          rescue => e
            puts "SYN protection cleanup error: #{e.message}"
          end
        end
      end
    end

    def calculate_syn_block_rate
      return 0 if @stats[:syn_packets_detected] == 0
      (@stats[:packets_blocked].to_f / @stats[:syn_packets_detected]) * 100
    end

    def calculate_protection_effectiveness
      total_syns = @stats[:syn_packets_detected]
      return 0 if total_syns == 0
      
      legitimate_rate = (@stats[:legitimate_connections].to_f / total_syns) * 100
      100 - legitimate_rate  # Higher is better (more attacks blocked)
    end
  end

  # SynFloodDefense provides high-level DDoS protection interface
  # Integrates with firewall and traffic shaping for comprehensive defense
  class SynFloodDefense
    attr_reader :protection, :defense_enabled, :integration_stats

    def initialize(firewall: nil, traffic_shaper: nil, **protection_options)
      @protection = TcpSynProtection.new(**protection_options)
      @firewall = firewall
      @traffic_shaper = traffic_shaper
      @defense_enabled = true
      @mutex = Mutex.new
      
      @integration_stats = {
        firewall_blocks: 0,
        traffic_shaped_syns: 0,
        total_integrations: 0,
        defense_activations: 0
      }
    end

    # Process packet through comprehensive SYN defense
    def defend_against_syn_flood(ipv4_packet, tcp_segment)
      return :allowed unless @defense_enabled
      
      @mutex.synchronize { @integration_stats[:total_integrations] += 1 }
      
      # Primary SYN flood protection
      protection_result = @protection.process_tcp_packet(ipv4_packet, tcp_segment)
      
      case protection_result
      when :blocked
        @mutex.synchronize { @integration_stats[:defense_activations] += 1 }
        
        # Integrate with firewall if available
        if @firewall
          @firewall.add_dynamic_rule(
            action: :drop,
            source_ip: ipv4_packet.source_ip,
            duration: 300,  # 5 minute block
            reason: "SYN flood protection"
          )
          @mutex.synchronize { @integration_stats[:firewall_blocks] += 1 }
        end
        
        # Integrate with traffic shaping if available
        if @traffic_shaper && tcp_segment.syn_flag
          @traffic_shaper.add_classification_rule(
            source_ip: ipv4_packet.source_ip,
            traffic_class: :background,  # Lowest priority
            action: :rate_limit
          )
          @mutex.synchronize { @integration_stats[:traffic_shaped_syns] += 1 }
        end
        
        :blocked
      when :allowed
        :allowed
      end
    end

    # Enable/disable comprehensive defense
    def defense_enabled=(enabled)
      @mutex.synchronize { @defense_enabled = enabled }
      @protection.protection_enabled = enabled
    end

    # Get defense status and statistics
    def defense_status
      protection_stats = @protection.protection_statistics
      
      @mutex.synchronize do
        {
          defense_enabled: @defense_enabled,
          protection_status: @protection.protection_status,
          integration_stats: @integration_stats,
          protection_effectiveness: protection_stats[:protection_effectiveness],
          active_blocks: @protection.tracker.blocked_ips.size,
          firewall_integrated: !@firewall.nil?,
          traffic_shaper_integrated: !@traffic_shaper.nil?
        }
      end
    end

    # Analyze current attack landscape
    def attack_landscape
      attack_analysis = @protection.attack_analysis
      
      # Enhanced analysis with defense context
      attack_analysis.map do |attack|
        attack.merge(
          defense_action: @protection.tracker.blocked_ip?(attack[:source_ip]) ? :blocked : :monitoring,
          threat_level: calculate_threat_level(attack)
        )
      end
    end

    # Update defense configuration
    def update_defense_config(**config)
      @protection.update_protection_config(**config)
    end

    # Shutdown defense systems
    def shutdown_defense!
      @protection.shutdown!
      @mutex.synchronize { @defense_enabled = false }
    end

    private

    def calculate_threat_level(attack_pattern)
      score = 0
      score += attack_pattern[:attempt_count] * 2
      score += attack_pattern[:target_ports].size * 5
      score += attack_pattern[:syn_rate] * 10
      
      case score
      when 0..20 then :low
      when 21..50 then :medium  
      when 51..100 then :high
      else :critical
      end
    end
  end
end
# frozen_string_literal: true

module AetherPacket
  # TokenBucket implements rate limiting using the token bucket algorithm
  # Provides smooth traffic shaping and burst control for QoS
  class TokenBucket
    attr_reader :capacity, :refill_rate, :current_tokens, :last_refill, :stats

    def initialize(capacity_bytes:, refill_rate_bps:, initial_tokens: nil)
      @capacity = capacity_bytes          # Maximum bucket capacity in bytes
      @refill_rate = refill_rate_bps      # Token refill rate in bytes per second
      @current_tokens = initial_tokens || capacity_bytes
      @last_refill = Time.now
      @mutex = Mutex.new                  # Thread safety for concurrent access
      
      @stats = {
        tokens_consumed: 0,
        packets_allowed: 0,
        packets_dropped: 0,
        bytes_allowed: 0,
        bytes_dropped: 0,
        bucket_empty_count: 0,
        last_reset: Time.now
      }
    end

    # Attempt to consume tokens for packet transmission
    def consume(bytes)
      @mutex.synchronize do
        refill_tokens!
        
        if @current_tokens >= bytes
          @current_tokens -= bytes
          @stats[:tokens_consumed] += bytes
          @stats[:packets_allowed] += 1
          @stats[:bytes_allowed] += bytes
          true
        else
          @stats[:packets_dropped] += 1
          @stats[:bytes_dropped] += bytes
          @stats[:bucket_empty_count] += 1 if @current_tokens == 0
          false
        end
      end
    end

    # Check if tokens are available without consuming
    def tokens_available?(bytes)
      @mutex.synchronize do
        refill_tokens!
        @current_tokens >= bytes
      end
    end

    # Get current token count
    def available_tokens
      @mutex.synchronize do
        refill_tokens!
        @current_tokens
      end
    end

    # Get bucket utilization percentage
    def utilization_percentage
      @mutex.synchronize do
        refill_tokens!
        ((@capacity - @current_tokens).to_f / @capacity) * 100
      end
    end

    # Reset bucket to full capacity
    def reset!
      @mutex.synchronize do
        @current_tokens = @capacity
        @last_refill = Time.now
      end
    end

    # Update bucket parameters
    def update_capacity(new_capacity)
      @mutex.synchronize do
        @capacity = new_capacity
        @current_tokens = [@current_tokens, new_capacity].min
      end
    end

    def update_refill_rate(new_rate)
      @mutex.synchronize do
        refill_tokens!
        @refill_rate = new_rate
      end
    end

    # Get token bucket statistics
    def bucket_stats
      @mutex.synchronize do
        duration = Time.now - @stats[:last_reset]
        
        @stats.merge(
          capacity: @capacity,
          refill_rate: @refill_rate,
          current_tokens: @current_tokens,
          utilization: utilization_percentage,
          duration: duration,
          avg_rate_bps: duration > 0 ? @stats[:bytes_allowed] / duration : 0,
          drop_rate: @stats[:packets_dropped] > 0 ? 
                    (@stats[:packets_dropped].to_f / (@stats[:packets_allowed] + @stats[:packets_dropped])) * 100 : 0
        )
      end
    end

    # Reset statistics
    def reset_stats!
      @mutex.synchronize do
        @stats[:tokens_consumed] = 0
        @stats[:packets_allowed] = 0
        @stats[:packets_dropped] = 0
        @stats[:bytes_allowed] = 0
        @stats[:bytes_dropped] = 0
        @stats[:bucket_empty_count] = 0
        @stats[:last_reset] = Time.now
      end
    end

    private

    # Refill tokens based on elapsed time
    def refill_tokens!
      now = Time.now
      elapsed = now - @last_refill
      
      if elapsed > 0
        tokens_to_add = (elapsed * @refill_rate).to_i
        @current_tokens = [@current_tokens + tokens_to_add, @capacity].min
        @last_refill = now
      end
    end
  end

  # TrafficShaper manages multiple token buckets for different traffic classes
  # Implements hierarchical QoS with priority queuing
  class TrafficShaper
    # Traffic classes with priorities
    PRIORITY_HIGH = 1
    PRIORITY_NORMAL = 2
    PRIORITY_LOW = 3

    # QoS classes
    QOS_INTERACTIVE = :interactive    # Low latency (SSH, DNS, ICMP)
    QOS_BULK = :bulk                 # High throughput (HTTP, FTP)
    QOS_BACKGROUND = :background     # Best effort (P2P, backups)
    QOS_CRITICAL = :critical         # Network control (routing protocols)

    attr_reader :shapers, :classification_rules, :stats

    def initialize(total_bandwidth_bps)
      @total_bandwidth = total_bandwidth_bps
      @shapers = {}
      @classification_rules = []
      
      # Default traffic classes
      setup_default_classes
      
      @stats = {
        total_packets: 0,
        shaped_packets: 0,
        dropped_packets: 0,
        bytes_shaped: 0,
        bytes_dropped: 0,
        class_distribution: Hash.new(0)
      }
    end

    # Add traffic shaper for specific class
    def add_shaper(class_name, bandwidth_bps, burst_bytes = nil)
      burst_bytes ||= bandwidth_bps / 8  # 1 second worth of data
      
      @shapers[class_name] = {
        bucket: TokenBucket.new(
          capacity_bytes: burst_bytes,
          refill_rate_bps: bandwidth_bps
        ),
        priority: get_class_priority(class_name),
        bandwidth: bandwidth_bps
      }
    end

    # Add traffic classification rule
    def add_classification_rule(traffic_class:, protocol: nil, source_port: nil, 
                              destination_port: nil, dscp: nil, priority: 100)
      @classification_rules << {
        traffic_class: traffic_class,
        protocol: protocol,
        source_port: source_port,
        destination_port: destination_port,
        dscp: dscp,
        priority: priority
      }
      
      # Sort rules by priority (lower number = higher priority)
      @classification_rules.sort_by! { |rule| rule[:priority] }
    end

    # Shape packet based on classification
    def shape_packet(ipv4_packet, transport_packet)
      @stats[:total_packets] += 1
      packet_size = ipv4_packet.total_length
      
      # Classify packet
      traffic_class = classify_packet(ipv4_packet, transport_packet)
      @stats[:class_distribution][traffic_class] += 1
      
      # Find appropriate shaper
      shaper_info = @shapers[traffic_class]
      unless shaper_info
        # Use default shaper if no specific class found
        traffic_class = QOS_BACKGROUND
        shaper_info = @shapers[traffic_class]
      end
      
      # Attempt to consume tokens
      if shaper_info[:bucket].consume(packet_size)
        @stats[:shaped_packets] += 1
        @stats[:bytes_shaped] += packet_size
        
        {
          action: :allow,
          traffic_class: traffic_class,
          delay_ms: 0,  # Could implement delay-based shaping
          priority: shaper_info[:priority]
        }
      else
        @stats[:dropped_packets] += 1
        @stats[:bytes_dropped] += packet_size
        
        {
          action: :drop,
          traffic_class: traffic_class,
          reason: :rate_limit_exceeded,
          priority: shaper_info[:priority]
        }
      end
    end

    # Get comprehensive shaping statistics
    def shaping_stats
      shaper_stats = {}
      @shapers.each do |class_name, shaper_info|
        shaper_stats[class_name] = shaper_info[:bucket].bucket_stats.merge(
          priority: shaper_info[:priority],
          bandwidth_bps: shaper_info[:bandwidth]
        )
      end
      
      @stats.merge(
        total_bandwidth: @total_bandwidth,
        active_shapers: @shapers.size,
        classification_rules: @classification_rules.size,
        shaper_stats: shaper_stats,
        drop_rate: calculate_drop_rate
      )
    end

    # Update bandwidth allocation
    def update_class_bandwidth(class_name, new_bandwidth_bps, new_burst = nil)
      return unless @shapers[class_name]
      
      shaper_info = @shapers[class_name]
      shaper_info[:bandwidth] = new_bandwidth_bps
      shaper_info[:bucket].update_refill_rate(new_bandwidth_bps)
      
      if new_burst
        shaper_info[:bucket].update_capacity(new_burst)
      end
    end

    # Reset all shapers
    def reset_all_shapers!
      @shapers.each_value { |info| info[:bucket].reset! }
    end

    # Reset statistics
    def reset_stats!
      @stats[:total_packets] = 0
      @stats[:shaped_packets] = 0
      @stats[:dropped_packets] = 0
      @stats[:bytes_shaped] = 0
      @stats[:bytes_dropped] = 0
      @stats[:class_distribution].clear
      
      @shapers.each_value { |info| info[:bucket].reset_stats! }
    end

    private

    # Setup default QoS classes
    def setup_default_classes
      # Allocate bandwidth percentages
      critical_bw = @total_bandwidth * 0.10    # 10% for critical
      interactive_bw = @total_bandwidth * 0.30 # 30% for interactive  
      bulk_bw = @total_bandwidth * 0.50        # 50% for bulk
      background_bw = @total_bandwidth * 0.10  # 10% for background
      
      add_shaper(QOS_CRITICAL, critical_bw, critical_bw / 4)
      add_shaper(QOS_INTERACTIVE, interactive_bw, interactive_bw / 2)
      add_shaper(QOS_BULK, bulk_bw, bulk_bw)
      add_shaper(QOS_BACKGROUND, background_bw, background_bw / 4)
      
      # Add default classification rules
      add_default_classification_rules
    end

    # Add default classification rules
    def add_default_classification_rules
      # Critical traffic (routing protocols, network management)
      add_classification_rule(traffic_class: QOS_CRITICAL, protocol: :icmp, priority: 10)
      add_classification_rule(traffic_class: QOS_CRITICAL, destination_port: 179, priority: 10) # BGP
      add_classification_rule(traffic_class: QOS_CRITICAL, destination_port: 161, priority: 10) # SNMP
      
      # Interactive traffic (low latency requirements)
      add_classification_rule(traffic_class: QOS_INTERACTIVE, destination_port: 22, priority: 20)  # SSH
      add_classification_rule(traffic_class: QOS_INTERACTIVE, destination_port: 53, priority: 20)  # DNS
      add_classification_rule(traffic_class: QOS_INTERACTIVE, destination_port: 443, priority: 30) # HTTPS
      
      # Bulk traffic (high throughput)
      add_classification_rule(traffic_class: QOS_BULK, destination_port: 80, priority: 40)   # HTTP
      add_classification_rule(traffic_class: QOS_BULK, destination_port: 21, priority: 40)   # FTP
      add_classification_rule(traffic_class: QOS_BULK, destination_port: 25, priority: 40)   # SMTP
      
      # Background traffic (best effort)
      add_classification_rule(traffic_class: QOS_BACKGROUND, protocol: :tcp, priority: 50)   # Default TCP
      add_classification_rule(traffic_class: QOS_BACKGROUND, protocol: :udp, priority: 50)   # Default UDP
    end

    # Classify packet based on rules
    def classify_packet(ipv4_packet, transport_packet)
      packet_info = extract_packet_classification_info(ipv4_packet, transport_packet)
      
      @classification_rules.each do |rule|
        if rule_matches?(rule, packet_info)
          return rule[:traffic_class]
        end
      end
      
      # Default classification
      QOS_BACKGROUND
    end

    # Check if rule matches packet
    def rule_matches?(rule, packet_info)
      # Check protocol
      return false if rule[:protocol] && rule[:protocol] != packet_info[:protocol]
      
      # Check source port
      return false if rule[:source_port] && rule[:source_port] != packet_info[:source_port]
      
      # Check destination port
      return false if rule[:destination_port] && rule[:destination_port] != packet_info[:destination_port]
      
      # Check DSCP (if available)
      return false if rule[:dscp] && rule[:dscp] != packet_info[:dscp]
      
      true
    end

    # Extract packet information for classification
    def extract_packet_classification_info(ipv4_packet, transport_packet)
      info = {
        protocol: :ip,
        source_port: 0,
        destination_port: 0,
        dscp: (ipv4_packet.type_of_service >> 2) & 0x3f
      }
      
      case transport_packet
      when TcpSegment
        info[:protocol] = :tcp
        info[:source_port] = transport_packet.source_port
        info[:destination_port] = transport_packet.destination_port
      when UdpDatagram
        info[:protocol] = :udp
        info[:source_port] = transport_packet.source_port
        info[:destination_port] = transport_packet.destination_port
      when IcmpPacket
        info[:protocol] = :icmp
      end
      
      info
    end

    # Get priority for traffic class
    def get_class_priority(class_name)
      case class_name
      when QOS_CRITICAL then PRIORITY_HIGH
      when QOS_INTERACTIVE then PRIORITY_HIGH
      when QOS_BULK then PRIORITY_NORMAL
      when QOS_BACKGROUND then PRIORITY_LOW
      else PRIORITY_NORMAL
      end
    end

    # Calculate overall drop rate
    def calculate_drop_rate
      return 0 if @stats[:total_packets] == 0
      (@stats[:dropped_packets].to_f / @stats[:total_packets]) * 100
    end
  end
end
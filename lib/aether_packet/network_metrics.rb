# frozen_string_literal: true

module AetherPacket
  # MetricPoint represents a single measurement at a point in time
  class MetricPoint
    attr_reader :timestamp, :value, :tags

    def initialize(value, tags: {})
      @timestamp = Time.now
      @value = value.to_f
      @tags = tags.dup.freeze
    end

    # Convert to hash for serialization
    def to_hash
      {
        timestamp: @timestamp.to_f,
        value: @value,
        tags: @tags
      }
    end
  end

  # TimeSeries manages a series of metric points over time
  class TimeSeries
    attr_reader :name, :points, :max_points

    def initialize(name, max_points: 1000)
      @name = name
      @points = []
      @max_points = max_points
      @mutex = Mutex.new
    end

    # Add a new metric point
    def add_point(value, tags: {})
      @mutex.synchronize do
        @points << MetricPoint.new(value, tags: tags)
        
        # Keep only the most recent points
        if @points.size > @max_points
          @points.shift
        end
      end
    end

    # Get points within time range
    def points_in_range(start_time, end_time)
      @mutex.synchronize do
        @points.select do |point|
          point.timestamp >= start_time && point.timestamp <= end_time
        end
      end
    end

    # Get recent points
    def recent_points(count: 100)
      @mutex.synchronize { @points.last(count) }
    end

    # Calculate statistics for recent points
    def statistics(count: 100)
      recent = recent_points(count: count)
      return {} if recent.empty?
      
      values = recent.map(&:value)
      
      {
        count: values.size,
        min: values.min,
        max: values.max,
        avg: values.sum / values.size,
        latest: values.last,
        first_timestamp: recent.first.timestamp,
        last_timestamp: recent.last.timestamp
      }
    end

    # Calculate rate of change (per second)
    def rate(window_seconds: 60)
      cutoff_time = Time.now - window_seconds
      window_points = points_in_range(cutoff_time, Time.now)
      
      return 0 if window_points.size < 2
      
      first_point = window_points.first
      last_point = window_points.last
      time_diff = last_point.timestamp - first_point.timestamp
      
      return 0 if time_diff <= 0
      
      value_diff = last_point.value - first_point.value
      value_diff / time_diff
    end

    # Clear old points
    def clear_old_points!(max_age_seconds)
      cutoff_time = Time.now - max_age_seconds
      
      @mutex.synchronize do
        @points.select! { |point| point.timestamp > cutoff_time }
      end
    end

    # Export time series data
    def export_data
      @mutex.synchronize do
        {
          name: @name,
          max_points: @max_points,
          current_points: @points.size,
          points: @points.map(&:to_hash)
        }
      end
    end
  end

  # NetworkMetrics collects and manages network performance metrics
  class NetworkMetrics
    attr_reader :metrics, :enabled

    def initialize(retention_seconds: 3600, max_points_per_metric: 1000)
      @metrics = {}
      @retention_seconds = retention_seconds
      @max_points_per_metric = max_points_per_metric
      @enabled = true
      @cleanup_thread = nil
      @mutex = Mutex.new
      
      initialize_default_metrics
      start_cleanup_thread
    end

    # Record a metric value
    def record_metric(name, value, tags: {})
      return unless @enabled
      
      metric_name = name.to_s
      
      @mutex.synchronize do
        @metrics[metric_name] ||= TimeSeries.new(metric_name, max_points: @max_points_per_metric)
      end
      
      @metrics[metric_name].add_point(value, tags: tags)
    end

    # Increment a counter metric
    def increment_counter(name, amount = 1, tags: {})
      current_value = get_latest_value(name) || 0
      record_metric(name, current_value + amount, tags: tags)
    end

    # Record a gauge metric (absolute value)
    def record_gauge(name, value, tags: {})
      record_metric(name, value, tags: tags)
    end

    # Record timing metric in milliseconds
    def record_timing(name, duration_ms, tags: {})
      record_metric(name, duration_ms, tags: tags.merge(unit: 'ms'))
    end

    # Record bandwidth metric in bytes/second
    def record_bandwidth(name, bytes_per_second, tags: {})
      record_metric(name, bytes_per_second, tags: tags.merge(unit: 'bps'))
    end

    # Get latest value for a metric
    def get_latest_value(name)
      metric = @metrics[name.to_s]
      return nil unless metric
      
      recent_points = metric.recent_points(count: 1)
      recent_points.empty? ? nil : recent_points.first.value
    end

    # Get statistics for a metric
    def get_metric_stats(name, count: 100)
      metric = @metrics[name.to_s]
      return {} unless metric
      
      metric.statistics(count: count)
    end

    # Get rate for a metric
    def get_metric_rate(name, window_seconds: 60)
      metric = @metrics[name.to_s]
      return 0 unless metric
      
      metric.rate(window_seconds: window_seconds)
    end

    # Get all metric names
    def metric_names
      @mutex.synchronize { @metrics.keys }
    end

    # Get comprehensive metrics summary
    def metrics_summary
      summary = {}
      
      @mutex.synchronize do
        @metrics.each do |name, metric|
          summary[name] = metric.statistics.merge(
            rate_per_second: metric.rate(window_seconds: 60)
          )
        end
      end
      
      summary
    end

    # Export all metrics data
    def export_metrics
      @mutex.synchronize do
        {
          retention_seconds: @retention_seconds,
          max_points_per_metric: @max_points_per_metric,
          enabled: @enabled,
          metrics: @metrics.transform_values(&:export_data)
        }
      end
    end

    # Enable/disable metrics collection
    def enabled=(state)
      @mutex.synchronize { @enabled = state }
    end

    # Clear all metrics
    def clear_all_metrics!
      @mutex.synchronize { @metrics.clear }
      initialize_default_metrics
    end

    # Network-specific metric recording methods
    def record_packet_metrics(packet_size, direction: :rx)
      timestamp = Time.now
      
      case direction
      when :rx
        record_metric('network.packets.rx', get_latest_value('network.packets.rx').to_i + 1)
        record_metric('network.bytes.rx', get_latest_value('network.bytes.rx').to_i + packet_size)
      when :tx
        record_metric('network.packets.tx', get_latest_value('network.packets.tx').to_i + 1)
        record_metric('network.bytes.tx', get_latest_value('network.bytes.tx').to_i + packet_size)
      end
    end

    def record_protocol_metrics(protocol, packet_size)
      protocol_key = "protocol.#{protocol.downcase}"
      increment_counter("#{protocol_key}.packets")
      record_metric("#{protocol_key}.bytes", get_latest_value("#{protocol_key}.bytes").to_i + packet_size)
    end

    def record_connection_metrics(action)
      case action
      when :established
        increment_counter('connections.established')
        record_gauge('connections.active', get_latest_value('connections.active').to_i + 1)
      when :closed
        increment_counter('connections.closed')
        record_gauge('connections.active', [get_latest_value('connections.active').to_i - 1, 0].max)
      when :failed
        increment_counter('connections.failed')
      end
    end

    def record_security_metrics(event_type)
      case event_type
      when :firewall_block
        increment_counter('security.firewall.blocks')
      when :ids_alert
        increment_counter('security.ids.alerts')
      when :syn_flood_block
        increment_counter('security.syn_flood.blocks')
      when :dns_sinkhole
        increment_counter('security.dns.sinkhole')
      end
    end

    # Calculate network utilization percentages
    def network_utilization(interface_speed_bps = 1_000_000_000)  # Default 1Gbps
      rx_rate = get_metric_rate('network.bytes.rx', window_seconds: 60) * 8  # Convert to bits
      tx_rate = get_metric_rate('network.bytes.tx', window_seconds: 60) * 8
      
      {
        rx_utilization_percent: (rx_rate / interface_speed_bps * 100).round(2),
        tx_utilization_percent: (tx_rate / interface_speed_bps * 100).round(2),
        total_utilization_percent: ((rx_rate + tx_rate) / interface_speed_bps * 100).round(2)
      }
    end

    # Get performance dashboard data
    def dashboard_data
      {
        timestamp: Time.now,
        network: {
          packets_per_second: get_metric_rate('network.packets.rx') + get_metric_rate('network.packets.tx'),
          bytes_per_second: get_metric_rate('network.bytes.rx') + get_metric_rate('network.bytes.tx'),
          utilization: network_utilization
        },
        security: {
          firewall_blocks_per_minute: get_metric_rate('security.firewall.blocks', window_seconds: 60),
          ids_alerts_per_minute: get_metric_rate('security.ids.alerts', window_seconds: 60),
          active_connections: get_latest_value('connections.active') || 0
        },
        protocols: get_protocol_breakdown,
        top_metrics: get_top_metrics_by_rate
      }
    end

    # Shutdown metrics collection
    def shutdown!
      @enabled = false
      
      if @cleanup_thread
        @cleanup_thread.kill
        @cleanup_thread.join
        @cleanup_thread = nil
      end
    end

    private

    def initialize_default_metrics
      # Network metrics
      record_metric('network.packets.rx', 0)
      record_metric('network.packets.tx', 0)
      record_metric('network.bytes.rx', 0)
      record_metric('network.bytes.tx', 0)
      
      # Connection metrics
      record_metric('connections.active', 0)
      record_metric('connections.established', 0)
      record_metric('connections.closed', 0)
      record_metric('connections.failed', 0)
      
      # Security metrics
      record_metric('security.firewall.blocks', 0)
      record_metric('security.ids.alerts', 0)
      record_metric('security.syn_flood.blocks', 0)
      record_metric('security.dns.sinkhole', 0)
      
      # Protocol metrics
      %w[tcp udp icmp arp].each do |protocol|
        record_metric("protocol.#{protocol}.packets", 0)
        record_metric("protocol.#{protocol}.bytes", 0)
      end
    end

    def start_cleanup_thread
      @cleanup_thread = Thread.new do
        loop do
          sleep(300)  # Cleanup every 5 minutes
          
          begin
            @metrics.each_value do |metric|
              metric.clear_old_points!(@retention_seconds)
            end
          rescue => e
            puts "Metrics cleanup error: #{e.message}"
          end
        end
      end
    end

    def get_protocol_breakdown
      protocols = {}
      
      %w[tcp udp icmp arp].each do |protocol|
        packets = get_metric_rate("protocol.#{protocol}.packets")
        bytes = get_metric_rate("protocol.#{protocol}.bytes")
        
        protocols[protocol] = {
          packets_per_second: packets,
          bytes_per_second: bytes
        }
      end
      
      protocols
    end

    def get_top_metrics_by_rate(limit: 10)
      rates = {}
      
      @metrics.each do |name, metric|
        rate = metric.rate(window_seconds: 60)
        rates[name] = rate if rate > 0
      end
      
      rates.sort_by { |_, rate| -rate }.first(limit).to_h
    end
  end

  # MetricsCollector integrates metrics with network appliance components
  class MetricsCollector
    attr_reader :metrics, :collection_enabled

    def initialize(**metrics_options)
      @metrics = NetworkMetrics.new(**metrics_options)
      @collection_enabled = true
      @mutex = Mutex.new
    end

    # Collect metrics from network appliance
    def collect_appliance_metrics(appliance)
      return unless @collection_enabled
      
      # NAT metrics
      if appliance.respond_to?(:nat_engine)
        nat_stats = appliance.nat_engine.translation_stats rescue {}
        @metrics.record_gauge('nat.active_translations', nat_stats[:active_translations] || 0)
        @metrics.record_gauge('nat.translation_rate', nat_stats[:translations_per_second] || 0)
      end
      
      # Firewall metrics
      if appliance.respond_to?(:firewall)
        firewall_stats = appliance.firewall.firewall_stats rescue {}
        @metrics.record_gauge('firewall.rules_count', firewall_stats[:total_rules] || 0)
        @metrics.record_gauge('firewall.blocked_packets', firewall_stats[:packets_blocked] || 0)
      end
      
      # Traffic shaper metrics
      if appliance.respond_to?(:traffic_shaper)
        shaper_stats = appliance.traffic_shaper.traffic_stats rescue {}
        @metrics.record_gauge('qos.packets_shaped', shaper_stats[:packets_shaped] || 0)
        @metrics.record_gauge('qos.queue_utilization', shaper_stats.dig(:queue_stats, :utilization) || 0)
      end
    end

    # Enable/disable metrics collection
    def collection_enabled=(state)
      @mutex.synchronize { @collection_enabled = state }
      @metrics.enabled = state
    end

    # Get comprehensive metrics report
    def comprehensive_report
      {
        collection_enabled: @collection_enabled,
        metrics_summary: @metrics.metrics_summary,
        dashboard_data: @metrics.dashboard_data,
        system_health: calculate_system_health
      }
    end

    # Reset all collected metrics
    def reset_metrics!
      @metrics.clear_all_metrics!
    end

    private

    def calculate_system_health
      # Simple health calculation based on key metrics
      health_score = 100
      
      # Check error rates
      error_metrics = %w[connections.failed security.firewall.blocks security.ids.alerts]
      error_metrics.each do |metric|
        rate = @metrics.get_metric_rate(metric)
        health_score -= 5 if rate > 10  # More than 10 errors/sec
      end
      
      # Check utilization
      utilization = @metrics.network_utilization
      total_util = utilization[:total_utilization_percent]
      health_score -= 20 if total_util > 90  # Very high utilization
      health_score -= 10 if total_util > 70  # High utilization
      
      [health_score, 0].max
    end
  end
end
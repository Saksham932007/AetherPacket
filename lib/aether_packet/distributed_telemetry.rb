# frozen_string_literal: true

require 'json'
require 'zlib'
require 'digest'

module AetherPacket
  # TelemetryCollector aggregates network telemetry data from multiple sources
  class TelemetryCollector
    attr_reader :data_streams, :collector_stats, :storage_backend

    def initialize(config = {})
      @config = config
      @data_streams = {}
      @collector_stats = {
        total_data_points: 0,
        streams_active: 0,
        bytes_collected: 0,
        samples_per_second: 0,
        compression_ratio: 0.0,
        storage_operations: 0
      }
      @storage_backend = initialize_storage_backend(config[:storage])
      @processing_pipeline = []
      @alerting_rules = []
      @mutex = Mutex.new
      @running = false
      
      initialize_default_streams
    end

    # Start telemetry collection
    def start
      @running = true
      @collector_thread = Thread.new { run_collection_loop }
      @aggregation_thread = Thread.new { run_aggregation_loop }
      @storage_thread = Thread.new { run_storage_loop }
      
      puts "Telemetry Collector started"
      true
    end

    # Stop telemetry collection
    def stop
      @running = false
      @collector_thread&.join
      @aggregation_thread&.join
      @storage_thread&.join
      
      puts "Telemetry Collector stopped"
      true
    end

    # Register new telemetry stream
    def register_stream(stream_id, config)
      @mutex.synchronize do
        @data_streams[stream_id] = {
          id: stream_id,
          type: config[:type],
          source: config[:source],
          interval: config[:interval] || 1,
          format: config[:format] || :json,
          compression: config[:compression] || false,
          buffer_size: config[:buffer_size] || 1000,
          buffer: [],
          last_collection: nil,
          data_points_collected: 0,
          bytes_collected: 0,
          created_at: Time.now
        }
        
        @collector_stats[:streams_active] += 1
      end
      
      stream_id
    end

    # Collect telemetry data point
    def collect_data_point(stream_id, data_point)
      stream = @data_streams[stream_id]
      return false unless stream
      
      # Enrich data point with metadata
      enriched_data = enrich_data_point(data_point, stream)
      
      @mutex.synchronize do
        # Add to stream buffer
        stream[:buffer] << enriched_data
        stream[:data_points_collected] += 1
        stream[:bytes_collected] += calculate_data_size(enriched_data)
        stream[:last_collection] = Time.now
        
        # Update global stats
        @collector_stats[:total_data_points] += 1
        @collector_stats[:bytes_collected] += calculate_data_size(enriched_data)
        
        # Flush buffer if full
        if stream[:buffer].size >= stream[:buffer_size]
          flush_stream_buffer(stream_id)
        end
      end
      
      # Process through pipeline
      process_through_pipeline(enriched_data, stream)
      
      true
    end

    # Query telemetry data
    def query_data(query_params)
      start_time = Time.now
      
      result = @storage_backend.query(query_params)
      
      {
        data: result[:data],
        metadata: result[:metadata],
        query_time_ms: ((Time.now - start_time) * 1000).round(2),
        total_points: result[:total_points],
        filtered_points: result[:filtered_points]
      }
    end

    # Add processing stage to pipeline
    def add_processing_stage(stage_name, processor)
      @processing_pipeline << {
        name: stage_name,
        processor: processor,
        added_at: Time.now,
        invocations: 0
      }
    end

    # Add alerting rule
    def add_alerting_rule(rule_id, rule_config)
      @alerting_rules << {
        id: rule_id,
        config: rule_config,
        triggered_count: 0,
        last_triggered: nil,
        created_at: Time.now
      }
      
      rule_id
    end

    # Get telemetry statistics
    def get_telemetry_stats
      @mutex.synchronize do
        # Calculate samples per second
        current_time = Time.now
        time_window = 60  # 1 minute window
        recent_samples = @data_streams.values.sum do |stream|
          if stream[:last_collection] && (current_time - stream[:last_collection]) < time_window
            stream[:data_points_collected] * (time_window / (current_time - stream[:created_at]))
          else
            0
          end
        end
        
        @collector_stats[:samples_per_second] = (recent_samples / time_window).round(2)
        
        {
          collector_stats: @collector_stats.dup,
          stream_count: @data_streams.size,
          active_streams: @data_streams.values.count { |s| s[:last_collection] && (current_time - s[:last_collection]) < 30 },
          processing_stages: @processing_pipeline.size,
          alerting_rules: @alerting_rules.size,
          storage_backend: @storage_backend.class.name,
          uptime: current_time - @start_time
        }
      end
    end

    # Export telemetry data
    def export_data(export_config)
      format = export_config[:format] || :json
      time_range = export_config[:time_range]
      streams = export_config[:streams] || @data_streams.keys
      
      query_params = {
        streams: streams,
        start_time: time_range[:start],
        end_time: time_range[:end],
        format: format
      }
      
      exported_data = query_data(query_params)
      
      case format
      when :json
        JSON.pretty_generate(exported_data)
      when :csv
        convert_to_csv(exported_data)
      when :prometheus
        convert_to_prometheus_format(exported_data)
      else
        exported_data.to_s
      end
    end

    private

    def initialize_storage_backend(storage_config)
      backend_type = storage_config&.dig(:type) || :memory
      
      case backend_type
      when :memory
        MemoryStorageBackend.new(storage_config || {})
      when :timeseries
        TimeSeriesStorageBackend.new(storage_config || {})
      when :distributed
        DistributedStorageBackend.new(storage_config || {})
      else
        MemoryStorageBackend.new({})
      end
    end

    def initialize_default_streams
      # Register default telemetry streams
      register_stream(:network_metrics, {
        type: :metrics,
        source: :network_interface,
        interval: 1,
        format: :json
      })
      
      register_stream(:flow_statistics, {
        type: :flow_data,
        source: :flow_tracker,
        interval: 5,
        format: :binary,
        compression: true
      })
      
      register_stream(:security_events, {
        type: :events,
        source: :security_engine,
        interval: 0.1,
        format: :json
      })
      
      register_stream(:performance_metrics, {
        type: :metrics,
        source: :system_monitor,
        interval: 2,
        format: :json
      })
    end

    def run_collection_loop
      @start_time = Time.now
      
      while @running
        # Collect data from active streams
        @data_streams.each do |stream_id, stream|
          collect_stream_data(stream_id, stream)
        end
        
        # Update collection statistics
        update_collection_stats
        
        sleep(0.1)  # 100ms collection interval
      end
    end

    def run_aggregation_loop
      while @running
        # Perform data aggregation
        @data_streams.each do |stream_id, stream|
          if stream[:buffer].size > stream[:buffer_size] * 0.8
            aggregate_stream_data(stream_id, stream)
          end
        end
        
        sleep(1)  # 1 second aggregation interval
      end
    end

    def run_storage_loop
      while @running
        # Flush data to persistent storage
        @data_streams.each do |stream_id, stream|
          if stream[:buffer].any?
            store_stream_data(stream_id, stream)
          end
        end
        
        sleep(5)  # 5 second storage interval
      end
    end

    def collect_stream_data(stream_id, stream)
      case stream[:type]
      when :metrics
        collect_metrics_data(stream_id, stream)
      when :flow_data
        collect_flow_data(stream_id, stream)
      when :events
        collect_event_data(stream_id, stream)
      end
    end

    def collect_metrics_data(stream_id, stream)
      # Simulate collecting network metrics
      metrics_data = {
        timestamp: Time.now.to_f,
        interface_stats: {
          rx_packets: rand(1000),
          tx_packets: rand(1000),
          rx_bytes: rand(1_000_000),
          tx_bytes: rand(1_000_000),
          rx_errors: rand(10),
          tx_errors: rand(10)
        },
        cpu_utilization: rand(100),
        memory_utilization: rand(100),
        bandwidth_utilization: rand(100)
      }
      
      collect_data_point(stream_id, metrics_data)
    end

    def collect_flow_data(stream_id, stream)
      # Simulate collecting flow statistics
      flow_data = {
        timestamp: Time.now.to_f,
        flow_id: SecureRandom.hex(8),
        src_ip: "10.0.0.#{rand(254) + 1}",
        dst_ip: "10.0.1.#{rand(254) + 1}",
        src_port: rand(65535),
        dst_port: [80, 443, 22, 53].sample,
        protocol: [:tcp, :udp].sample,
        packets: rand(100),
        bytes: rand(10000),
        duration: rand(300),
        flags: [:active, :completed, :timeout].sample
      }
      
      collect_data_point(stream_id, flow_data)
    end

    def collect_event_data(stream_id, stream)
      # Simulate collecting security events
      event_data = {
        timestamp: Time.now.to_f,
        event_id: SecureRandom.hex(12),
        event_type: [:intrusion_attempt, :policy_violation, :anomaly_detected].sample,
        severity: [:low, :medium, :high, :critical].sample,
        source_ip: "10.0.0.#{rand(254) + 1}",
        target_ip: "10.0.1.#{rand(254) + 1}",
        description: "Security event detected",
        metadata: {
          rule_id: "rule_#{rand(1000)}",
          confidence: rand(100) / 100.0
        }
      }
      
      collect_data_point(stream_id, event_data)
    end

    def enrich_data_point(data_point, stream)
      {
        stream_id: stream[:id],
        stream_type: stream[:type],
        collection_timestamp: Time.now.to_f,
        source: stream[:source],
        data: data_point,
        metadata: {
          format: stream[:format],
          compressed: stream[:compression]
        }
      }
    end

    def calculate_data_size(data)
      JSON.generate(data).bytesize
    end

    def flush_stream_buffer(stream_id)
      stream = @data_streams[stream_id]
      return unless stream
      
      buffer_data = stream[:buffer].dup
      stream[:buffer].clear
      
      # Process buffer data
      process_buffer_data(stream_id, buffer_data)
    end

    def process_buffer_data(stream_id, buffer_data)
      # Apply compression if enabled
      stream = @data_streams[stream_id]
      
      if stream[:compression]
        compressed_data = compress_data(buffer_data)
        compression_ratio = compressed_data.size.to_f / JSON.generate(buffer_data).bytesize
        
        @mutex.synchronize do
          @collector_stats[:compression_ratio] = 
            (@collector_stats[:compression_ratio] + compression_ratio) / 2.0
        end
      end
      
      # Store in backend
      @storage_backend.store(stream_id, buffer_data)
      
      @mutex.synchronize do
        @collector_stats[:storage_operations] += 1
      end
    end

    def process_through_pipeline(data_point, stream)
      processed_data = data_point
      
      @processing_pipeline.each do |stage|
        processed_data = stage[:processor].call(processed_data, stream)
        stage[:invocations] += 1
        
        # Check alerting rules
        check_alerting_rules(processed_data)
      end
      
      processed_data
    end

    def check_alerting_rules(data_point)
      @alerting_rules.each do |rule|
        if evaluate_alerting_rule(rule[:config], data_point)
          trigger_alert(rule, data_point)
        end
      end
    end

    def evaluate_alerting_rule(rule_config, data_point)
      # Simple rule evaluation
      case rule_config[:type]
      when :threshold
        value = extract_metric_value(data_point, rule_config[:metric])
        case rule_config[:operator]
        when :gt
          value > rule_config[:threshold]
        when :lt
          value < rule_config[:threshold]
        when :eq
          value == rule_config[:threshold]
        else
          false
        end
      when :pattern
        data_point.to_s.match?(rule_config[:pattern])
      else
        false
      end
    end

    def trigger_alert(rule, data_point)
      rule[:triggered_count] += 1
      rule[:last_triggered] = Time.now
      
      alert = {
        rule_id: rule[:id],
        timestamp: Time.now,
        data_point: data_point,
        message: rule[:config][:message] || "Alert triggered",
        severity: rule[:config][:severity] || :medium
      }
      
      # Send alert (simplified - would integrate with alerting systems)
      puts "ALERT: #{alert[:message]} (Rule: #{rule[:id]})"
    end

    def extract_metric_value(data_point, metric_path)
      path_parts = metric_path.split('.')
      value = data_point
      
      path_parts.each do |part|
        value = value[part.to_sym] || value[part]
        break if value.nil?
      end
      
      value.to_f if value
    end

    def compress_data(data)
      Zlib::Deflate.deflate(JSON.generate(data))
    end

    def decompress_data(compressed_data)
      JSON.parse(Zlib::Inflate.inflate(compressed_data))
    end

    def aggregate_stream_data(stream_id, stream)
      return if stream[:buffer].empty?
      
      # Simple aggregation by time windows
      time_window = 60  # 1 minute windows
      current_time = Time.now
      window_start = (current_time.to_f / time_window).floor * time_window
      
      window_data = stream[:buffer].select do |data_point|
        data_point[:collection_timestamp] >= window_start
      end
      
      if window_data.size > 10  # Only aggregate if we have enough data
        aggregated = aggregate_data_points(window_data, stream[:type])
        
        # Replace buffer data with aggregated data
        stream[:buffer] = stream[:buffer] - window_data + [aggregated]
      end
    end

    def aggregate_data_points(data_points, stream_type)
      case stream_type
      when :metrics
        aggregate_metrics_data(data_points)
      when :flow_data
        aggregate_flow_data(data_points)
      when :events
        aggregate_event_data(data_points)
      else
        data_points.last  # Default: keep last data point
      end
    end

    def aggregate_metrics_data(data_points)
      # Aggregate metrics by calculating averages
      metrics = data_points.map { |dp| dp[:data] }
      
      {
        stream_id: data_points.first[:stream_id],
        stream_type: :metrics,
        collection_timestamp: Time.now.to_f,
        aggregation_window: data_points.size,
        data: {
          timestamp: Time.now.to_f,
          interface_stats: {
            rx_packets: average_metric(metrics, 'interface_stats.rx_packets'),
            tx_packets: average_metric(metrics, 'interface_stats.tx_packets'),
            rx_bytes: average_metric(metrics, 'interface_stats.rx_bytes'),
            tx_bytes: average_metric(metrics, 'interface_stats.tx_bytes')
          },
          cpu_utilization: average_metric(metrics, 'cpu_utilization'),
          memory_utilization: average_metric(metrics, 'memory_utilization'),
          bandwidth_utilization: average_metric(metrics, 'bandwidth_utilization')
        },
        metadata: {
          aggregated: true,
          original_count: data_points.size
        }
      }
    end

    def aggregate_flow_data(data_points)
      # Aggregate flow data by summing counters
      flows = data_points.map { |dp| dp[:data] }
      
      {
        stream_id: data_points.first[:stream_id],
        stream_type: :flow_data,
        collection_timestamp: Time.now.to_f,
        aggregation_window: data_points.size,
        data: {
          timestamp: Time.now.to_f,
          total_flows: flows.size,
          total_packets: flows.sum { |f| f[:packets] || 0 },
          total_bytes: flows.sum { |f| f[:bytes] || 0 },
          protocols: flows.group_by { |f| f[:protocol] }.transform_values(&:size),
          top_destinations: flows.group_by { |f| f[:dst_ip] }
                                  .transform_values(&:size)
                                  .sort_by { |_, count| -count }
                                  .first(5)
        },
        metadata: {
          aggregated: true,
          original_count: data_points.size
        }
      }
    end

    def aggregate_event_data(data_points)
      # Aggregate events by grouping by type and severity
      events = data_points.map { |dp| dp[:data] }
      
      {
        stream_id: data_points.first[:stream_id],
        stream_type: :events,
        collection_timestamp: Time.now.to_f,
        aggregation_window: data_points.size,
        data: {
          timestamp: Time.now.to_f,
          total_events: events.size,
          event_types: events.group_by { |e| e[:event_type] }.transform_values(&:size),
          severities: events.group_by { |e| e[:severity] }.transform_values(&:size),
          top_sources: events.group_by { |e| e[:source_ip] }
                            .transform_values(&:size)
                            .sort_by { |_, count| -count }
                            .first(5)
        },
        metadata: {
          aggregated: true,
          original_count: data_points.size
        }
      }
    end

    def average_metric(metrics, path)
      values = metrics.map { |m| extract_nested_value(m, path) }.compact
      return 0 if values.empty?
      
      values.sum / values.size.to_f
    end

    def extract_nested_value(hash, path)
      path_parts = path.split('.')
      value = hash
      
      path_parts.each do |part|
        value = value[part.to_sym] || value[part]
        break if value.nil?
      end
      
      value
    end

    def store_stream_data(stream_id, stream)
      return if stream[:buffer].empty?
      
      @storage_backend.store(stream_id, stream[:buffer].dup)
      stream[:buffer].clear
    end

    def update_collection_stats
      # Update real-time collection statistics
      current_time = Time.now
      
      # Calculate samples per second over last minute
      recent_samples = @data_streams.values.sum do |stream|
        if stream[:last_collection] && (current_time - stream[:last_collection]) < 60
          stream[:data_points_collected] * (60.0 / (current_time - stream[:created_at]))
        else
          0
        end
      end
      
      @mutex.synchronize do
        @collector_stats[:samples_per_second] = (recent_samples / 60.0).round(2)
        @collector_stats[:streams_active] = @data_streams.values.count do |stream|
          stream[:last_collection] && (current_time - stream[:last_collection]) < 30
        end
      end
    end

    def convert_to_csv(data)
      # Convert telemetry data to CSV format
      return "" if data[:data].empty?
      
      headers = data[:data].first.keys
      csv_lines = [headers.join(',')]
      
      data[:data].each do |row|
        csv_lines << headers.map { |h| row[h] }.join(',')
      end
      
      csv_lines.join("\n")
    end

    def convert_to_prometheus_format(data)
      # Convert to Prometheus exposition format
      prometheus_lines = []
      
      data[:data].each do |data_point|
        if data_point[:stream_type] == :metrics
          metrics = data_point[:data]
          timestamp = (data_point[:collection_timestamp] * 1000).to_i
          
          # Convert each metric to Prometheus format
          metrics.each do |metric_name, value|
            next unless value.is_a?(Numeric)
            
            prometheus_lines << "aether_#{metric_name} #{value} #{timestamp}"
          end
        end
      end
      
      prometheus_lines.join("\n")
    end
  end

  # Storage backends for telemetry data
  class MemoryStorageBackend
    def initialize(config)
      @config = config
      @data_store = {}
      @max_size = config[:max_size] || 100_000
      @mutex = Mutex.new
    end

    def store(stream_id, data_points)
      @mutex.synchronize do
        @data_store[stream_id] ||= []
        @data_store[stream_id].concat(data_points)
        
        # Enforce size limits
        if @data_store[stream_id].size > @max_size
          @data_store[stream_id] = @data_store[stream_id].last(@max_size)
        end
      end
    end

    def query(params)
      @mutex.synchronize do
        streams = params[:streams] || @data_store.keys
        start_time = params[:start_time]
        end_time = params[:end_time]
        
        results = []
        
        streams.each do |stream_id|
          stream_data = @data_store[stream_id] || []
          
          filtered_data = stream_data.select do |data_point|
            timestamp = data_point[:collection_timestamp]
            
            (start_time.nil? || timestamp >= start_time.to_f) &&
            (end_time.nil? || timestamp <= end_time.to_f)
          end
          
          results.concat(filtered_data)
        end
        
        {
          data: results.sort_by { |dp| dp[:collection_timestamp] },
          metadata: {
            total_streams: streams.size,
            query_timestamp: Time.now
          },
          total_points: results.size,
          filtered_points: results.size
        }
      end
    end
  end

  class TimeSeriesStorageBackend
    def initialize(config)
      @config = config
      @time_buckets = {}
      @bucket_size = config[:bucket_size] || 3600  # 1 hour buckets
      @retention_period = config[:retention_period] || 86400 * 7  # 1 week
      @mutex = Mutex.new
    end

    def store(stream_id, data_points)
      @mutex.synchronize do
        data_points.each do |data_point|
          timestamp = data_point[:collection_timestamp]
          bucket_key = generate_bucket_key(stream_id, timestamp)
          
          @time_buckets[bucket_key] ||= []
          @time_buckets[bucket_key] << data_point
        end
        
        # Clean up old buckets
        cleanup_old_buckets
      end
    end

    def query(params)
      @mutex.synchronize do
        streams = params[:streams] || []
        start_time = params[:start_time]
        end_time = params[:end_time]
        
        results = []
        
        # Find relevant time buckets
        bucket_keys = find_bucket_keys(streams, start_time, end_time)
        
        bucket_keys.each do |bucket_key|
          bucket_data = @time_buckets[bucket_key] || []
          
          filtered_data = bucket_data.select do |data_point|
            timestamp = data_point[:collection_timestamp]
            
            (start_time.nil? || timestamp >= start_time.to_f) &&
            (end_time.nil? || timestamp <= end_time.to_f)
          end
          
          results.concat(filtered_data)
        end
        
        {
          data: results.sort_by { |dp| dp[:collection_timestamp] },
          metadata: {
            buckets_queried: bucket_keys.size,
            query_timestamp: Time.now
          },
          total_points: results.size,
          filtered_points: results.size
        }
      end
    end

    private

    def generate_bucket_key(stream_id, timestamp)
      bucket_time = (timestamp / @bucket_size).floor * @bucket_size
      "#{stream_id}_#{bucket_time}"
    end

    def find_bucket_keys(streams, start_time, end_time)
      keys = []
      
      streams.each do |stream_id|
        start_bucket = start_time ? (start_time.to_f / @bucket_size).floor * @bucket_size : 0
        end_bucket = end_time ? (end_time.to_f / @bucket_size).floor * @bucket_size : Time.now.to_f
        
        bucket_time = start_bucket
        while bucket_time <= end_bucket
          keys << "#{stream_id}_#{bucket_time}"
          bucket_time += @bucket_size
        end
      end
      
      keys.select { |key| @time_buckets.key?(key) }
    end

    def cleanup_old_buckets
      cutoff_time = Time.now.to_f - @retention_period
      
      @time_buckets.delete_if do |bucket_key, _|
        bucket_timestamp = bucket_key.split('_').last.to_f
        bucket_timestamp < cutoff_time
      end
    end
  end

  class DistributedStorageBackend
    def initialize(config)
      @config = config
      @nodes = config[:nodes] || []
      @replication_factor = config[:replication_factor] || 2
      @consistency_level = config[:consistency_level] || :quorum
      @node_states = {}
      @mutex = Mutex.new
      
      initialize_nodes
    end

    def store(stream_id, data_points)
      # Implement consistent hashing for data distribution
      target_nodes = select_storage_nodes(stream_id)
      
      storage_results = []
      
      target_nodes.each do |node|
        result = store_to_node(node, stream_id, data_points)
        storage_results << { node: node, success: result }
      end
      
      # Check if we meet consistency requirements
      successful_stores = storage_results.count { |r| r[:success] }
      required_success = calculate_required_success(target_nodes.size)
      
      successful_stores >= required_success
    end

    def query(params)
      # Query from multiple nodes and merge results
      query_nodes = select_query_nodes
      
      query_results = []
      
      query_nodes.each do |node|
        result = query_from_node(node, params)
        query_results << result if result
      end
      
      # Merge and deduplicate results
      merged_results = merge_query_results(query_results)
      
      {
        data: merged_results[:data],
        metadata: {
          nodes_queried: query_nodes.size,
          successful_queries: query_results.size,
          query_timestamp: Time.now
        },
        total_points: merged_results[:total_points],
        filtered_points: merged_results[:filtered_points]
      }
    end

    private

    def initialize_nodes
      @nodes.each do |node|
        @node_states[node] = {
          id: node,
          status: :healthy,
          last_seen: Time.now,
          storage_operations: 0,
          query_operations: 0
        }
      end
    end

    def select_storage_nodes(stream_id)
      # Simple consistent hashing
      hash_value = Digest::SHA256.hexdigest(stream_id).to_i(16)
      node_count = @nodes.size
      
      return @nodes if node_count <= @replication_factor
      
      start_index = hash_value % node_count
      selected_nodes = []
      
      @replication_factor.times do |i|
        node_index = (start_index + i) % node_count
        selected_nodes << @nodes[node_index]
      end
      
      selected_nodes
    end

    def select_query_nodes
      # Query from healthy nodes
      @nodes.select { |node| @node_states[node][:status] == :healthy }
    end

    def store_to_node(node, stream_id, data_points)
      # Simulate storing to distributed node
      begin
        @mutex.synchronize do
          @node_states[node][:storage_operations] += 1
          @node_states[node][:last_seen] = Time.now
        end
        
        # In real implementation, would make network call to node
        true
      rescue => e
        @mutex.synchronize do
          @node_states[node][:status] = :unhealthy
        end
        false
      end
    end

    def query_from_node(node, params)
      # Simulate querying from distributed node
      begin
        @mutex.synchronize do
          @node_states[node][:query_operations] += 1
          @node_states[node][:last_seen] = Time.now
        end
        
        # In real implementation, would make network call to node
        # Return simulated data
        {
          data: [],
          node: node,
          timestamp: Time.now
        }
      rescue => e
        @mutex.synchronize do
          @node_states[node][:status] = :unhealthy
        end
        nil
      end
    end

    def calculate_required_success(total_nodes)
      case @consistency_level
      when :all
        total_nodes
      when :quorum
        (total_nodes / 2) + 1
      when :one
        1
      else
        1
      end
    end

    def merge_query_results(query_results)
      all_data = []
      total_points = 0
      
      query_results.each do |result|
        all_data.concat(result[:data]) if result[:data]
        total_points += result[:data]&.size || 0
      end
      
      # Remove duplicates based on timestamp and stream_id
      unique_data = all_data.uniq do |data_point|
        "#{data_point[:stream_id]}_#{data_point[:collection_timestamp]}"
      end
      
      {
        data: unique_data.sort_by { |dp| dp[:collection_timestamp] },
        total_points: total_points,
        filtered_points: unique_data.size
      }
    end
  end
end
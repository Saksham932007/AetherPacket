# frozen_string_literal: true

module AetherPacket
  # BufferPool manages reusable memory buffers to reduce allocations
  class BufferPool
    DEFAULT_BUFFER_SIZE = 65536  # 64KB - typical MTU size
    DEFAULT_POOL_SIZE = 100

    def initialize(buffer_size: DEFAULT_BUFFER_SIZE, pool_size: DEFAULT_POOL_SIZE)
      @buffer_size = buffer_size
      @pool_size = pool_size
      @available_buffers = []
      @in_use_buffers = Set.new
      @mutex = Mutex.new
      @stats = {
        buffers_created: 0,
        buffers_reused: 0,
        peak_usage: 0,
        allocation_hits: 0,
        allocation_misses: 0
      }
      
      # Pre-allocate initial buffers
      pool_size.times { create_new_buffer }
    end

    # Get a buffer from the pool
    def get_buffer
      @mutex.synchronize do
        buffer = if @available_buffers.empty?
          @stats[:allocation_misses] += 1
          create_new_buffer
        else
          @stats[:allocation_hits] += 1
          @stats[:buffers_reused] += 1
          @available_buffers.pop
        end
        
        @in_use_buffers << buffer
        @stats[:peak_usage] = [@stats[:peak_usage], @in_use_buffers.size].max
        buffer
      end
    end

    # Return a buffer to the pool
    def return_buffer(buffer)
      @mutex.synchronize do
        return unless @in_use_buffers.delete(buffer)
        
        # Reset buffer for reuse
        buffer.clear
        @available_buffers << buffer if @available_buffers.size < @pool_size
      end
    end

    # Execute block with managed buffer
    def with_buffer(&block)
      buffer = get_buffer
      begin
        yield(buffer)
      ensure
        return_buffer(buffer)
      end
    end

    # Get pool statistics
    def pool_stats
      @mutex.synchronize do
        {
          buffer_size: @buffer_size,
          pool_size: @pool_size,
          available_buffers: @available_buffers.size,
          in_use_buffers: @in_use_buffers.size,
          hit_rate: calculate_hit_rate,
          **@stats
        }
      end
    end

    # Reset pool statistics
    def reset_stats!
      @mutex.synchronize do
        @stats.each_key { |key| @stats[key] = 0 }
      end
    end

    private

    def create_new_buffer
      buffer = String.new(capacity: @buffer_size)
      @stats[:buffers_created] += 1
      buffer
    end

    def calculate_hit_rate
      total_requests = @stats[:allocation_hits] + @stats[:allocation_misses]
      return 0 if total_requests == 0
      (@stats[:allocation_hits].to_f / total_requests * 100).round(2)
    end
  end

  # FastPacketProcessor optimizes packet processing pipelines
  class FastPacketProcessor
    def initialize(buffer_pool: nil)
      @buffer_pool = buffer_pool || BufferPool.new
      @processing_stats = {
        packets_processed: 0,
        processing_time_total: 0,
        fastest_packet_time: Float::INFINITY,
        slowest_packet_time: 0
      }
      @mutex = Mutex.new
    end

    # Process packet with minimal allocations
    def process_packet_fast(packet_data, &processor_block)
      start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      
      result = @buffer_pool.with_buffer do |buffer|
        # Copy packet data to managed buffer
        buffer.replace(packet_data)
        
        # Process with provided block
        processor_block.call(buffer) if processor_block
      end
      
      # Update timing statistics
      processing_time = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start_time
      update_processing_stats(processing_time)
      
      result
    end

    # Batch process multiple packets efficiently
    def process_packet_batch(packet_batch)
      results = []
      start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      
      packet_batch.each do |packet_data|
        result = @buffer_pool.with_buffer do |buffer|
          buffer.replace(packet_data)
          yield(buffer) if block_given?
        end
        results << result
      end
      
      total_time = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start_time
      batch_size = packet_batch.size
      
      @mutex.synchronize do
        @processing_stats[:packets_processed] += batch_size
        @processing_stats[:processing_time_total] += total_time
      end
      
      {
        results: results,
        batch_size: batch_size,
        total_time: total_time,
        packets_per_second: batch_size / total_time
      }
    end

    # Get processing performance statistics
    def processing_stats
      @mutex.synchronize do
        avg_time = if @processing_stats[:packets_processed] > 0
          @processing_stats[:processing_time_total] / @processing_stats[:packets_processed]
        else
          0
        end
        
        @processing_stats.merge(
          average_packet_time: avg_time,
          packets_per_second: calculate_packets_per_second,
          buffer_pool_stats: @buffer_pool.pool_stats
        )
      end
    end

    private

    def update_processing_stats(processing_time)
      @mutex.synchronize do
        @processing_stats[:packets_processed] += 1
        @processing_stats[:processing_time_total] += processing_time
        @processing_stats[:fastest_packet_time] = [
          @processing_stats[:fastest_packet_time], processing_time
        ].min
        @processing_stats[:slowest_packet_time] = [
          @processing_stats[:slowest_packet_time], processing_time
        ].max
      end
    end

    def calculate_packets_per_second
      return 0 if @processing_stats[:processing_time_total] == 0
      @processing_stats[:packets_processed] / @processing_stats[:processing_time_total]
    end
  end

  # PacketCache implements intelligent caching for packet processing results
  class PacketCache
    def initialize(max_size: 1000, ttl_seconds: 60)
      @max_size = max_size
      @ttl_seconds = ttl_seconds
      @cache = {}
      @access_times = {}
      @mutex = Mutex.new
      @stats = {
        hits: 0,
        misses: 0,
        evictions: 0,
        size: 0
      }
    end

    # Get cached result or compute new one
    def fetch(key, &block)
      @mutex.synchronize do
        # Check for existing valid entry
        if @cache.key?(key) && !expired?(key)
          @access_times[key] = Time.now
          @stats[:hits] += 1
          return @cache[key]
        end
        
        # Cache miss - compute new value
        @stats[:misses] += 1
        result = yield
        
        # Store in cache
        store_in_cache(key, result)
        result
      end
    end

    # Store value in cache with LRU eviction
    def store(key, value)
      @mutex.synchronize { store_in_cache(key, value) }
    end

    # Check if key exists and is valid
    def key?(key)
      @mutex.synchronize { @cache.key?(key) && !expired?(key) }
    end

    # Get cache statistics
    def cache_stats
      @mutex.synchronize do
        total_requests = @stats[:hits] + @stats[:misses]
        hit_rate = total_requests > 0 ? (@stats[:hits].to_f / total_requests * 100).round(2) : 0
        
        {
          max_size: @max_size,
          current_size: @cache.size,
          ttl_seconds: @ttl_seconds,
          hit_rate: hit_rate,
          **@stats
        }
      end
    end

    # Clear expired entries
    def cleanup_expired!
      @mutex.synchronize do
        expired_keys = @cache.keys.select { |key| expired?(key) }
        expired_keys.each { |key| remove_key(key) }
        expired_keys.size
      end
    end

    # Clear entire cache
    def clear!
      @mutex.synchronize do
        @cache.clear
        @access_times.clear
        @stats[:size] = 0
      end
    end

    private

    def store_in_cache(key, value)
      # Remove existing entry if present
      remove_key(key) if @cache.key?(key)
      
      # Evict LRU entry if at capacity
      if @cache.size >= @max_size
        evict_lru_entry
      end
      
      # Store new entry
      @cache[key] = value
      @access_times[key] = Time.now
      @stats[:size] = @cache.size
    end

    def expired?(key)
      return true unless @access_times.key?(key)
      Time.now - @access_times[key] > @ttl_seconds
    end

    def evict_lru_entry
      lru_key = @access_times.min_by { |_, time| time }&.first
      if lru_key
        remove_key(lru_key)
        @stats[:evictions] += 1
      end
    end

    def remove_key(key)
      @cache.delete(key)
      @access_times.delete(key)
    end
  end

  # HighPerformanceNetworkInterface optimizes network operations
  class HighPerformanceNetworkInterface < NetworkInterface
    def initialize(interface_name, optimization_level: :high)
      super(interface_name)
      @optimization_level = optimization_level
      @buffer_pool = BufferPool.new(buffer_size: 65536, pool_size: 200)
      @packet_processor = FastPacketProcessor.new(buffer_pool: @buffer_pool)
      @packet_cache = PacketCache.new(max_size: 5000, ttl_seconds: 30)
      @batch_size = optimization_level == :extreme ? 32 : 16
    end

    # Optimized packet reading with batching
    def read_packets_optimized(max_packets: @batch_size)
      packets = []
      start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      
      max_packets.times do
        begin
          packet_data = read_raw_packet
          break unless packet_data
          
          # Use buffer pool for processing
          processed_packet = @packet_processor.process_packet_fast(packet_data) do |buffer|
            # Minimal packet validation
            next nil if buffer.bytesize < 14  # Minimum Ethernet frame
            buffer.dup  # Return copy for further processing
          end
          
          packets << processed_packet if processed_packet
        rescue IO::WaitReadable
          break  # No more packets available
        end
      end
      
      batch_time = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start_time
      
      {
        packets: packets,
        batch_size: packets.size,
        batch_time: batch_time,
        packets_per_second: packets.size / [batch_time, 0.001].max
      }
    end

    # Cached packet parsing for repeated similar packets
    def parse_packet_cached(packet_data)
      # Create cache key based on packet header
      cache_key = generate_packet_cache_key(packet_data)
      
      @packet_cache.fetch(cache_key) do
        # Full packet parsing (expensive operation)
        parse_full_packet(packet_data)
      end
    end

    # Get optimization statistics
    def optimization_stats
      {
        optimization_level: @optimization_level,
        batch_size: @batch_size,
        buffer_pool: @buffer_pool.pool_stats,
        packet_processor: @packet_processor.processing_stats,
        packet_cache: @packet_cache.cache_stats
      }
    end

    # Cleanup optimization resources
    def cleanup_optimization_resources!
      @packet_cache.cleanup_expired!
      @buffer_pool.reset_stats!
    end

    private

    def generate_packet_cache_key(packet_data)
      # Simple cache key based on packet header
      # In real implementation, would be more sophisticated
      packet_data[0..20].unpack1('H*') if packet_data.bytesize >= 20
    end

    def parse_full_packet(packet_data)
      # Full packet parsing implementation
      # This would parse Ethernet, IP, TCP/UDP headers
      {
        ethernet: packet_data[0..13],
        ip: packet_data[14..33],
        transport: packet_data[34..53],
        payload: packet_data[54..-1]
      }
    end
  end

  # PerformanceMonitor tracks system performance metrics
  class PerformanceMonitor
    def initialize
      @metrics = {}
      @start_time = Time.now
      @mutex = Mutex.new
    end

    # Start timing operation
    def start_timer(operation)
      @mutex.synchronize do
        @metrics[operation] ||= {
          count: 0,
          total_time: 0,
          min_time: Float::INFINITY,
          max_time: 0,
          current_start: nil
        }
        @metrics[operation][:current_start] = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end
    end

    # End timing operation
    def end_timer(operation)
      end_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      
      @mutex.synchronize do
        metric = @metrics[operation]
        return unless metric&.dig(:current_start)
        
        duration = end_time - metric[:current_start]
        
        metric[:count] += 1
        metric[:total_time] += duration
        metric[:min_time] = [metric[:min_time], duration].min
        metric[:max_time] = [metric[:max_time], duration].max
        metric[:current_start] = nil
      end
    end

    # Time operation with block
    def time_operation(operation, &block)
      start_timer(operation)
      begin
        result = yield
        result
      ensure
        end_timer(operation)
      end
    end

    # Get performance report
    def performance_report
      @mutex.synchronize do
        uptime = Time.now - @start_time
        
        report = {
          uptime_seconds: uptime,
          operations: {}
        }
        
        @metrics.each do |operation, metric|
          avg_time = metric[:total_time] / [metric[:count], 1].max
          ops_per_second = metric[:count] / uptime
          
          report[:operations][operation] = {
            count: metric[:count],
            total_time: metric[:total_time],
            average_time: avg_time,
            min_time: metric[:min_time] == Float::INFINITY ? 0 : metric[:min_time],
            max_time: metric[:max_time],
            operations_per_second: ops_per_second
          }
        end
        
        report
      end
    end

    # Reset all metrics
    def reset!
      @mutex.synchronize do
        @metrics.clear
        @start_time = Time.now
      end
    end
  end

  # OptimizedNetworkAppliance integrates all performance optimizations
  class OptimizedNetworkAppliance < NetworkAppliance
    def initialize(**options)
      super(**options)
      @optimization_level = options[:optimization_level] || :high
      @performance_monitor = PerformanceMonitor.new
      @optimized_interfaces = {}
      @global_buffer_pool = BufferPool.new(buffer_size: 65536, pool_size: 500)
      
      setup_performance_optimizations
    end

    # Process packets with full optimization pipeline
    def process_packets_optimized(max_batch_size: 64)
      @performance_monitor.time_operation(:packet_processing) do
        all_packets = []
        
        @optimized_interfaces.each do |name, interface|
          batch_result = interface.read_packets_optimized(max_packets: max_batch_size)
          all_packets.concat(batch_result[:packets])
        end
        
        # Process packets through appliance pipeline
        all_packets.each do |packet_data|
          process_single_packet_optimized(packet_data)
        end
        
        {
          total_packets: all_packets.size,
          processing_stats: @performance_monitor.performance_report
        }
      end
    end

    # Get comprehensive optimization statistics
    def optimization_report
      {
        optimization_level: @optimization_level,
        performance_monitor: @performance_monitor.performance_report,
        global_buffer_pool: @global_buffer_pool.pool_stats,
        interface_stats: @optimized_interfaces.transform_values(&:optimization_stats),
        memory_usage: get_memory_usage,
        recommendations: generate_optimization_recommendations
      }
    end

    # Apply runtime optimizations
    def optimize_runtime!
      # Cleanup expired cache entries
      @optimized_interfaces.each_value(&:cleanup_optimization_resources!)
      
      # Reset performance counters
      @performance_monitor.reset!
      
      # Trigger garbage collection
      GC.start
      
      puts "Runtime optimizations applied"
    end

    private

    def setup_performance_optimizations
      # Convert regular interfaces to optimized versions
      @interfaces.each do |name, interface|
        if interface.is_a?(NetworkInterface)
          @optimized_interfaces[name] = HighPerformanceNetworkInterface.new(
            interface.name,
            optimization_level: @optimization_level
          )
        end
      end
    end

    def process_single_packet_optimized(packet_data)
      @performance_monitor.time_operation(:single_packet) do
        @global_buffer_pool.with_buffer do |buffer|
          buffer.replace(packet_data)
          
          # Optimized packet processing pipeline
          # Would integrate with existing firewall, NAT, etc.
          
          buffer.bytesize  # Return processed size
        end
      end
    end

    def get_memory_usage
      # Simple memory usage reporting
      {
        object_count: ObjectSpace.count_objects,
        gc_stats: GC.stat
      }
    end

    def generate_optimization_recommendations
      recommendations = []
      report = @performance_monitor.performance_report
      
      # Analyze performance metrics
      report[:operations].each do |operation, stats|
        if stats[:average_time] > 0.01  # 10ms threshold
          recommendations << "Consider optimizing #{operation} (avg: #{(stats[:average_time] * 1000).round(2)}ms)"
        end
        
        if stats[:operations_per_second] < 100
          recommendations << "Low throughput for #{operation} (#{stats[:operations_per_second].round(1)}/sec)"
        end
      end
      
      # Buffer pool recommendations
      pool_stats = @global_buffer_pool.pool_stats
      if pool_stats[:hit_rate] < 80
        recommendations << "Consider increasing buffer pool size (hit rate: #{pool_stats[:hit_rate]}%)"
      end
      
      recommendations.empty? ? ['Performance looks good!'] : recommendations
    end
  end
end
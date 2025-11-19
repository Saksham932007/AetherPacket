# frozen_string_literal: true

module AetherPacket
  # CircularBuffer implements lock-free ring buffer for high-performance packet queuing
  class CircularBuffer
    attr_reader :size, :head, :tail

    def initialize(size)
      @size = size.next_power_of_2  # Ensure power of 2 for efficient modulo
      @mask = @size - 1
      @buffer = Array.new(@size)
      @head = 0
      @tail = 0
    end

    # Lock-free enqueue operation
    def enqueue(item)
      current_tail = @tail
      next_tail = (current_tail + 1) & @mask
      
      return false if next_tail == @head  # Buffer full
      
      @buffer[current_tail] = item
      @tail = next_tail
      true
    end

    # Lock-free dequeue operation
    def dequeue
      current_head = @head
      return nil if current_head == @tail  # Buffer empty
      
      item = @buffer[current_head]
      @buffer[current_head] = nil  # Help GC
      @head = (current_head + 1) & @mask
      item
    end

    # Check if buffer is empty
    def empty?
      @head == @tail
    end

    # Check if buffer is full
    def full?
      ((@tail + 1) & @mask) == @head
    end

    # Get current utilization
    def utilization
      used = (@tail - @head) & @mask
      (used.to_f / @size) * 100
    end

    # Get available space
    def available_space
      @size - ((@tail - @head) & @mask) - 1
    end
  end

  # DpdkInterface provides DPDK-style zero-copy packet processing
  class DpdkInterface
    attr_reader :interface_name, :ring_buffers, :workers, :stats

    def initialize(interface_name, ring_buffer_size: 2048, worker_threads: nil)
      @interface_name = interface_name
      @ring_buffer_size = ring_buffer_size
      @worker_count = worker_threads || [Etc.nprocessors, 4].min
      @running = false
      
      # Create per-core packet rings
      @rx_rings = Array.new(@worker_count) { CircularBuffer.new(ring_buffer_size) }
      @tx_rings = Array.new(@worker_count) { CircularBuffer.new(ring_buffer_size) }
      @workers = []
      
      # Performance statistics
      @stats = {
        packets_received: 0,
        packets_transmitted: 0,
        packets_dropped: 0,
        ring_buffer_overruns: 0,
        worker_cycles: 0,
        avg_packet_size: 0,
        peak_pps: 0,
        current_pps: 0
      }
      
      @last_stats_time = Time.now
      @packet_count_window = []
    end

    # Start high-performance packet processing
    def start!
      return false if @running
      
      puts "Starting DPDK-style interface #{@interface_name} with #{@worker_count} workers"
      
      @running = true
      start_packet_workers
      start_stats_collector
      
      true
    end

    # Stop packet processing
    def stop!
      @running = false
      
      @workers.each(&:join)
      @workers.clear
      
      puts "Stopped DPDK interface #{@interface_name}"
    end

    # Enqueue packet for transmission (lock-free)
    def transmit_packet(packet_data, worker_id = 0)
      ring = @tx_rings[worker_id % @worker_count]
      
      if ring.enqueue(packet_data)
        @stats[:packets_transmitted] += 1
        true
      else
        @stats[:packets_dropped] += 1
        false
      end
    end

    # Bulk transmit for better performance
    def transmit_packet_batch(packet_batch, worker_id = 0)
      ring = @tx_rings[worker_id % @worker_count]
      transmitted = 0
      
      packet_batch.each do |packet_data|
        if ring.enqueue(packet_data)
          transmitted += 1
        else
          @stats[:packets_dropped] += 1
          break  # Ring full, stop trying
        end
      end
      
      @stats[:packets_transmitted] += transmitted
      transmitted
    end

    # Register packet processing callback
    def on_packet_received(&block)
      @packet_callback = block
    end

    # Get detailed performance statistics
    def performance_stats
      current_time = Time.now
      time_delta = current_time - @last_stats_time
      
      # Calculate packets per second
      if time_delta > 1.0
        pps = @packet_count_window.sum / time_delta
        @stats[:current_pps] = pps
        @stats[:peak_pps] = [@stats[:peak_pps], pps].max
        @packet_count_window.clear
        @last_stats_time = current_time
      end
      
      # Ring buffer utilization
      rx_utilization = @rx_rings.map(&:utilization).sum / @rx_rings.size
      tx_utilization = @tx_rings.map(&:utilization).sum / @tx_rings.size
      
      @stats.merge(
        worker_count: @worker_count,
        ring_buffer_size: @ring_buffer_size,
        rx_ring_utilization: rx_utilization.round(2),
        tx_ring_utilization: tx_utilization.round(2),
        running: @running
      )
    end

    # CPU affinity binding for performance
    def bind_worker_to_cpu(worker_id, cpu_core)
      begin
        # This would use native CPU affinity setting
        # For demo purposes, we'll just track the assignment
        puts "Binding worker #{worker_id} to CPU core #{cpu_core}"
        true
      rescue => e
        puts "Failed to bind worker to CPU: #{e.message}"
        false
      end
    end

    private

    def start_packet_workers
      @worker_count.times do |worker_id|
        @workers << Thread.new do
          Thread.current.name = "dpdk-worker-#{worker_id}"
          Thread.current.priority = 10  # Higher priority for packet processing
          
          # Bind to specific CPU core for NUMA optimization
          bind_worker_to_cpu(worker_id, worker_id % Etc.nprocessors)
          
          packet_processing_loop(worker_id)
        end
      end
    end

    def packet_processing_loop(worker_id)
      rx_ring = @rx_rings[worker_id]
      tx_ring = @tx_rings[worker_id]
      cycle_count = 0
      
      while @running
        cycle_count += 1
        packets_processed = 0
        
        # Process received packets (simulated for now)
        # In real DPDK, this would poll hardware queues
        packets_processed += process_rx_ring(rx_ring, worker_id)
        
        # Process transmit queue
        packets_processed += process_tx_ring(tx_ring, worker_id)
        
        # Yield CPU if no work to do
        if packets_processed == 0
          Thread.pass
          sleep(0.0001)  # 100 microseconds
        end
        
        # Update worker statistics
        @stats[:worker_cycles] += cycle_count if cycle_count % 10000 == 0
      end
    end

    def process_rx_ring(rx_ring, worker_id)
      packets_processed = 0
      batch_size = 32  # Process up to 32 packets per cycle
      
      batch_size.times do
        packet_data = rx_ring.dequeue
        break unless packet_data
        
        packets_processed += 1
        @stats[:packets_received] += 1
        @packet_count_window << 1
        
        # Update average packet size
        update_avg_packet_size(packet_data.bytesize)
        
        # Call registered packet handler
        @packet_callback&.call(packet_data, worker_id)
      end
      
      packets_processed
    end

    def process_tx_ring(tx_ring, worker_id)
      packets_processed = 0
      batch_size = 32
      
      # In real implementation, this would write to hardware
      batch_size.times do
        packet_data = tx_ring.dequeue
        break unless packet_data
        
        packets_processed += 1
        # Simulate packet transmission
        transmit_to_hardware(packet_data, worker_id)
      end
      
      packets_processed
    end

    def transmit_to_hardware(packet_data, worker_id)
      # Simulate hardware transmission
      # In real DPDK, this would write to NIC queues
      true
    end

    def update_avg_packet_size(packet_size)
      # Exponential moving average
      alpha = 0.1
      @stats[:avg_packet_size] = (@stats[:avg_packet_size] * (1 - alpha)) + (packet_size * alpha)
    end

    def start_stats_collector
      Thread.new do
        Thread.current.name = "dpdk-stats"
        
        while @running
          sleep(1)
          
          # Collect and reset periodic statistics
          # This could export to monitoring systems
          stats = performance_stats
          
          if stats[:current_pps] > 1000
            puts "DPDK #{@interface_name}: #{stats[:current_pps].round(0)} pps, " \
                 "RX util: #{stats[:rx_ring_utilization]}%, " \
                 "TX util: #{stats[:tx_ring_utilization]}%"
          end
        end
      end
    end
  end

  # LockFreePacketQueue implements high-performance packet queuing
  class LockFreePacketQueue
    def initialize(capacity: 4096)
      @capacity = capacity.next_power_of_2
      @mask = @capacity - 1
      @buffer = Array.new(@capacity)
      @head = 0
      @tail = 0
      @stats = {
        enqueued: 0,
        dequeued: 0,
        overruns: 0
      }
    end

    # Lock-free multi-producer enqueue
    def enqueue(packet)
      loop do
        current_tail = @tail
        next_tail = (current_tail + 1) & @mask
        
        if next_tail == @head
          @stats[:overruns] += 1
          return false  # Queue full
        end
        
        # Compare-and-swap simulation (would use atomic operations)
        if @tail == current_tail
          @buffer[current_tail] = packet
          @tail = next_tail
          @stats[:enqueued] += 1
          return true
        end
        
        # Retry if CAS failed
        Thread.pass
      end
    end

    # Lock-free single-consumer dequeue
    def dequeue
      current_head = @head
      return nil if current_head == @tail
      
      packet = @buffer[current_head]
      @buffer[current_head] = nil
      @head = (current_head + 1) & @mask
      @stats[:dequeued] += 1
      
      packet
    end

    # Bulk dequeue for better cache performance
    def dequeue_batch(max_count = 32)
      packets = []
      
      max_count.times do
        packet = dequeue
        break unless packet
        packets << packet
      end
      
      packets
    end

    # Queue statistics
    def queue_stats
      used_slots = (@tail - @head) & @mask
      
      {
        capacity: @capacity,
        used_slots: used_slots,
        utilization: (used_slots.to_f / @capacity * 100).round(2),
        **@stats
      }
    end
  end

  # HighPerformancePacketProcessor integrates DPDK-style processing
  class HighPerformancePacketProcessor
    attr_reader :interfaces, :global_stats

    def initialize(optimization_level: :extreme)
      @interfaces = {}
      @optimization_level = optimization_level
      @running = false
      @global_stats = {
        total_packets_processed: 0,
        total_processing_time: 0,
        peak_global_pps: 0
      }
    end

    # Add high-performance interface
    def add_interface(name, interface_name, **options)
      @interfaces[name] = DpdkInterface.new(interface_name, **options)
      
      # Register packet processing callback
      @interfaces[name].on_packet_received do |packet_data, worker_id|
        process_packet_high_performance(packet_data, name, worker_id)
      end
      
      @interfaces[name]
    end

    # Start all interfaces
    def start_all!
      return false if @running
      
      @running = true
      @interfaces.each_value(&:start!)
      
      puts "Started high-performance packet processing with #{@interfaces.size} interfaces"
      true
    end

    # Stop all interfaces
    def stop_all!
      @running = false
      @interfaces.each_value(&:stop!)
      puts "Stopped high-performance packet processing"
    end

    # Get comprehensive performance report
    def performance_report
      interface_stats = @interfaces.transform_values(&:performance_stats)
      
      total_pps = interface_stats.values.sum { |stats| stats[:current_pps] }
      @global_stats[:peak_global_pps] = [@global_stats[:peak_global_pps], total_pps].max
      
      {
        optimization_level: @optimization_level,
        running: @running,
        interface_count: @interfaces.size,
        total_current_pps: total_pps.round(0),
        interface_stats: interface_stats,
        global_stats: @global_stats,
        system_info: {
          cpu_cores: Etc.nprocessors,
          ruby_version: RUBY_VERSION,
          memory_usage: get_memory_usage
        }
      }
    end

    # Transmit packet through specific interface
    def transmit_packet(interface_name, packet_data, worker_id = 0)
      interface = @interfaces[interface_name]
      return false unless interface
      
      interface.transmit_packet(packet_data, worker_id)
    end

    private

    def process_packet_high_performance(packet_data, interface_name, worker_id)
      start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      
      # Minimal packet processing for maximum performance
      # This is where actual packet processing logic would go
      
      processing_time = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start_time
      
      @global_stats[:total_packets_processed] += 1
      @global_stats[:total_processing_time] += processing_time
      
      # Could forward to other components here
      true
    end

    def get_memory_usage
      {
        object_count: ObjectSpace.count_objects[:TOTAL],
        gc_count: GC.count
      }
    end
  end
end

# Extension for Integer to find next power of 2
class Integer
  def next_power_of_2
    return 1 if self <= 1
    
    n = self - 1
    n |= n >> 1
    n |= n >> 2
    n |= n >> 4
    n |= n >> 8
    n |= n >> 16
    n + 1
  end
end
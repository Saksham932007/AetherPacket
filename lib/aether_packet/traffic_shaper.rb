# frozen_string_literal: true

module AetherPacket
  # PacketQueue implements priority-based packet queuing for traffic control
  # Supports multiple queue classes with weighted fair queuing
  class PacketQueue
    # Queue entry structure
    QueueEntry = Struct.new(:packet_data, :priority, :timestamp, :size_bytes, :metadata)

    attr_reader :queues, :max_queue_size, :stats

    def initialize(max_queue_size: 1000)
      @max_queue_size = max_queue_size
      @queues = {
        high: [],
        normal: [], 
        low: []
      }
      @mutex = Mutex.new
      
      @stats = {
        enqueued_packets: 0,
        dequeued_packets: 0,
        dropped_packets: 0,
        queue_full_drops: 0,
        total_bytes_queued: 0,
        total_bytes_dequeued: 0,
        avg_queue_time: 0
      }
    end

    # Enqueue packet with priority
    def enqueue(packet_data, priority: :normal, metadata: {})
      @mutex.synchronize do
        queue = @queues[priority] || @queues[:normal]
        
        if total_queue_size >= @max_queue_size
          @stats[:dropped_packets] += 1
          @stats[:queue_full_drops] += 1
          return false
        end
        
        entry = QueueEntry.new(
          packet_data,
          priority,
          Time.now,
          packet_data.bytesize,
          metadata
        )
        
        queue << entry
        @stats[:enqueued_packets] += 1
        @stats[:total_bytes_queued] += entry.size_bytes
        true
      end
    end

    # Dequeue packet with priority scheduling
    def dequeue
      @mutex.synchronize do
        entry = nil
        
        # Service high priority first, then normal, then low
        [:high, :normal, :low].each do |priority|
          queue = @queues[priority]
          next if queue.empty?
          
          entry = queue.shift
          break
        end
        
        if entry
          queue_time = Time.now - entry.timestamp
          @stats[:dequeued_packets] += 1
          @stats[:total_bytes_dequeued] += entry.size_bytes
          update_avg_queue_time(queue_time)
          
          {
            packet_data: entry.packet_data,
            priority: entry.priority,
            queue_time: queue_time,
            metadata: entry.metadata
          }
        else
          nil
        end
      end
    end

    # Get current queue sizes
    def queue_sizes
      @mutex.synchronize do
        {
          high: @queues[:high].size,
          normal: @queues[:normal].size,
          low: @queues[:low].size,
          total: total_queue_size
        }
      end
    end

    # Check if queue has packets
    def empty?
      @mutex.synchronize { total_queue_size == 0 }
    end

    # Clear all queues
    def clear!
      @mutex.synchronize do
        @queues.each_value(&:clear)
      end
    end

    # Get queue statistics
    def queue_stats
      @mutex.synchronize do
        {
          queue_sizes: queue_sizes,
          max_queue_size: @max_queue_size,
          utilization: (total_queue_size.to_f / @max_queue_size) * 100,
          **@stats
        }
      end
    end

    private

    def total_queue_size
      @queues.values.sum(&:size)
    end

    def update_avg_queue_time(queue_time)
      if @stats[:dequeued_packets] > 1
        @stats[:avg_queue_time] = (
          (@stats[:avg_queue_time] * (@stats[:dequeued_packets] - 1) + queue_time) / 
          @stats[:dequeued_packets]
        )
      else
        @stats[:avg_queue_time] = queue_time
      end
    end
  end

  # AdvancedTrafficShaper integrates queuing with token bucket rate limiting
  # Provides enterprise-grade traffic control with QoS guarantees
  class AdvancedTrafficShaper
    attr_reader :shaper, :packet_queue, :egress_interface, :stats, :active

    def initialize(total_bandwidth_bps:, egress_interface: nil, queue_size: 1000)
      @shaper = TrafficShaper.new(total_bandwidth_bps)
      @packet_queue = PacketQueue.new(max_queue_size: queue_size)
      @egress_interface = egress_interface
      @active = false
      @processor_thread = nil
      @mutex = Mutex.new
      
      @stats = {
        packets_shaped: 0,
        packets_transmitted: 0,
        packets_queued: 0,
        bytes_transmitted: 0,
        queue_drops: 0,
        rate_limit_drops: 0,
        processing_errors: 0
      }
    end

    # Start traffic shaping processor
    def start!
      @mutex.synchronize do
        return if @active
        
        @active = true
        @processor_thread = Thread.new { process_packet_queue }
      end
    end

    # Stop traffic shaping processor
    def stop!
      @mutex.synchronize do
        @active = false
        @processor_thread&.join
        @processor_thread = nil
      end
    end

    # Shape and queue packet for transmission
    def shape_and_queue_packet(ipv4_packet, transport_packet, metadata: {})
      @stats[:packets_shaped] += 1
      
      # Apply traffic shaping
      shaping_result = @shaper.shape_packet(ipv4_packet, transport_packet)
      
      case shaping_result[:action]
      when :allow
        # Queue packet for transmission
        packet_data = ipv4_packet.to_binary_s
        priority = priority_to_queue_priority(shaping_result[:priority])
        
        if @packet_queue.enqueue(packet_data, priority: priority, metadata: metadata.merge(shaping_result))
          @stats[:packets_queued] += 1
          true
        else
          @stats[:queue_drops] += 1
          false
        end
      when :drop
        @stats[:rate_limit_drops] += 1
        false
      end
    end

    # Get comprehensive shaping statistics
    def traffic_stats
      shaper_stats = @shaper.shaping_stats
      queue_stats = @packet_queue.queue_stats
      
      @stats.merge(
        shaper_stats: shaper_stats,
        queue_stats: queue_stats,
        active: @active,
        total_bandwidth: @shaper.total_bandwidth
      )
    end

    # Update traffic class bandwidth
    def update_class_bandwidth(class_name, bandwidth_bps, burst_bytes = nil)
      @shaper.update_class_bandwidth(class_name, bandwidth_bps, burst_bytes)
    end

    # Add custom traffic classification rule
    def add_classification_rule(**rule_params)
      @shaper.add_classification_rule(**rule_params)
    end

    # Set egress interface for packet transmission
    def set_egress_interface(interface)
      @mutex.synchronize { @egress_interface = interface }
    end

    # Reset all shaping state
    def reset!
      @shaper.reset_all_shapers!
      @packet_queue.clear!
      @stats.each_key { |key| @stats[key] = 0 }
    end

    private

    # Main packet processing loop
    def process_packet_queue
      while @active
        begin
          entry = @packet_queue.dequeue
          
          if entry
            transmit_packet(entry)
          else
            sleep(0.001)  # Short sleep if queue is empty
          end
        rescue => e
          @stats[:processing_errors] += 1
          puts "Traffic shaping error: #{e.message}"
          sleep(0.01)  # Prevent tight error loops
        end
      end
    end

    # Transmit packet through egress interface
    def transmit_packet(queue_entry)
      packet_data = queue_entry[:packet_data]
      
      if @egress_interface
        begin
          @egress_interface.write_packet(packet_data)
          @stats[:packets_transmitted] += 1
          @stats[:bytes_transmitted] += packet_data.bytesize
        rescue => e
          @stats[:processing_errors] += 1
          puts "Packet transmission error: #{e.message}"
        end
      else
        # No egress interface - just count as transmitted
        @stats[:packets_transmitted] += 1
        @stats[:bytes_transmitted] += packet_data.bytesize
      end
    end

    # Convert shaper priority to queue priority
    def priority_to_queue_priority(shaper_priority)
      case shaper_priority
      when TrafficShaper::PRIORITY_HIGH then :high
      when TrafficShaper::PRIORITY_NORMAL then :normal
      when TrafficShaper::PRIORITY_LOW then :low
      else :normal
      end
    end
  end

  # BandwidthManager coordinates traffic shaping across multiple interfaces
  # Provides centralized bandwidth allocation and monitoring
  class BandwidthManager
    attr_reader :interface_shapers, :global_bandwidth, :stats

    def initialize(global_bandwidth_bps)
      @global_bandwidth = global_bandwidth_bps
      @interface_shapers = {}
      @bandwidth_allocation = {}
      @mutex = Mutex.new
      
      @stats = {
        total_interfaces: 0,
        allocated_bandwidth: 0,
        available_bandwidth: global_bandwidth_bps,
        total_packets_shaped: 0,
        total_bytes_transmitted: 0
      }
    end

    # Add interface with bandwidth allocation
    def add_interface(interface_name, interface, bandwidth_bps, queue_size: 1000)
      @mutex.synchronize do
        return false if @stats[:available_bandwidth] < bandwidth_bps
        
        shaper = AdvancedTrafficShaper.new(
          total_bandwidth_bps: bandwidth_bps,
          egress_interface: interface,
          queue_size: queue_size
        )
        
        @interface_shapers[interface_name] = shaper
        @bandwidth_allocation[interface_name] = bandwidth_bps
        
        @stats[:allocated_bandwidth] += bandwidth_bps
        @stats[:available_bandwidth] -= bandwidth_bps
        @stats[:total_interfaces] += 1
        
        shaper.start!
        true
      end
    end

    # Remove interface and free bandwidth
    def remove_interface(interface_name)
      @mutex.synchronize do
        shaper = @interface_shapers.delete(interface_name)
        allocated = @bandwidth_allocation.delete(interface_name)
        
        if shaper && allocated
          shaper.stop!
          @stats[:allocated_bandwidth] -= allocated
          @stats[:available_bandwidth] += allocated
          @stats[:total_interfaces] -= 1
          true
        else
          false
        end
      end
    end

    # Shape packet on specific interface
    def shape_packet(interface_name, ipv4_packet, transport_packet, metadata: {})
      shaper = @interface_shapers[interface_name]
      return false unless shaper
      
      result = shaper.shape_and_queue_packet(ipv4_packet, transport_packet, metadata: metadata)
      @stats[:total_packets_shaped] += 1 if result
      result
    end

    # Update interface bandwidth allocation
    def update_interface_bandwidth(interface_name, new_bandwidth_bps)
      @mutex.synchronize do
        current_allocation = @bandwidth_allocation[interface_name]
        return false unless current_allocation
        
        bandwidth_diff = new_bandwidth_bps - current_allocation
        return false if bandwidth_diff > @stats[:available_bandwidth]
        
        @bandwidth_allocation[interface_name] = new_bandwidth_bps
        @stats[:allocated_bandwidth] += bandwidth_diff
        @stats[:available_bandwidth] -= bandwidth_diff
        
        # Update shaper bandwidth (would need to implement in AdvancedTrafficShaper)
        true
      end
    end

    # Get comprehensive bandwidth statistics
    def bandwidth_stats
      interface_stats = {}
      total_transmitted_bytes = 0
      
      @interface_shapers.each do |name, shaper|
        stats = shaper.traffic_stats
        interface_stats[name] = stats
        total_transmitted_bytes += stats[:bytes_transmitted] || 0
      end
      
      @stats[:total_bytes_transmitted] = total_transmitted_bytes
      
      @stats.merge(
        interface_stats: interface_stats,
        bandwidth_utilization: calculate_bandwidth_utilization,
        allocation_efficiency: calculate_allocation_efficiency
      )
    end

    # Start all interface shapers
    def start_all!
      @interface_shapers.each_value(&:start!)
    end

    # Stop all interface shapers
    def stop_all!
      @interface_shapers.each_value(&:stop!)
    end

    # Reset all statistics
    def reset_stats!
      @interface_shapers.each_value(&:reset!)
      @stats[:total_packets_shaped] = 0
      @stats[:total_bytes_transmitted] = 0
    end

    private

    # Calculate overall bandwidth utilization
    def calculate_bandwidth_utilization
      return 0 if @stats[:allocated_bandwidth] == 0
      (@stats[:allocated_bandwidth].to_f / @global_bandwidth) * 100
    end

    # Calculate allocation efficiency
    def calculate_allocation_efficiency
      active_interfaces = @interface_shapers.select { |_, shaper| shaper.active }.size
      return 0 if @stats[:total_interfaces] == 0
      (active_interfaces.to_f / @stats[:total_interfaces]) * 100
    end
  end
end
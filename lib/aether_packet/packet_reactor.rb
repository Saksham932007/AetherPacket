# frozen_string_literal: true

module AetherPacket
  # PacketReactor implements high-performance non-blocking packet capture
  # Uses IO.select for efficient polling without CPU spinning
  class PacketReactor
    # Reactor states
    STOPPED = 0
    STARTING = 1  
    RUNNING = 2
    STOPPING = 3

    attr_reader :interfaces, :state, :stats

    def initialize(max_packet_size: 65536)
      @interfaces = {}
      @state = STOPPED
      @running = false
      @max_packet_size = max_packet_size
      @select_timeout = 0.1  # 100ms for responsive shutdown
      
      # Performance statistics
      @stats = {
        packets_received: 0,
        packets_dropped: 0,
        bytes_received: 0,
        loop_iterations: 0,
        last_reset: Time.now
      }

      # Packet processing callbacks
      @packet_handlers = []
      @error_handlers = []
    end

    # Add network interface to reactor
    def add_interface(interface_name, enable_promiscuous: true)
      raise NetworkError, "Interface #{interface_name} already added" if @interfaces.key?(interface_name)
      
      interface = NetworkInterface.new(interface_name)
      interface.enable_promiscuous! if enable_promiscuous
      
      @interfaces[interface_name] = interface
      interface
    end

    # Remove interface from reactor
    def remove_interface(interface_name)
      interface = @interfaces.delete(interface_name)
      interface&.close
      interface
    end

    # Register packet processing callback
    # Block receives: |interface_name, raw_packet_data, timestamp|
    def on_packet(&block)
      @packet_handlers << block if block
    end

    # Register error handling callback  
    # Block receives: |error, context|
    def on_error(&block)
      @error_handlers << block if block
    end

    # Start the reactor loop
    def start
      return false if @state != STOPPED
      
      raise NetworkError, "No interfaces configured" if @interfaces.empty?
      
      @state = STARTING
      @running = true
      @stats[:last_reset] = Time.now
      
      begin
        run_reactor_loop
      ensure
        cleanup_reactor
      end
    end

    # Stop the reactor loop gracefully  
    def stop
      return unless @running
      @running = false
      @state = STOPPING
    end

    # Check if reactor is running
    def running?
      @state == RUNNING
    end

    # Get performance statistics
    def performance_stats
      now = Time.now
      duration = now - @stats[:last_reset]
      
      @stats.merge(
        duration: duration,
        packets_per_second: duration > 0 ? @stats[:packets_received] / duration : 0,
        bytes_per_second: duration > 0 ? @stats[:bytes_received] / duration : 0
      )
    end

    # Reset statistics counters
    def reset_stats!
      @stats[:packets_received] = 0
      @stats[:packets_dropped] = 0  
      @stats[:bytes_received] = 0
      @stats[:loop_iterations] = 0
      @stats[:last_reset] = Time.now
    end

    private

    # Main reactor event loop
    def run_reactor_loop
      @state = RUNNING
      sockets = @interfaces.values.map(&:socket)
      
      while @running
        @stats[:loop_iterations] += 1
        
        # Use IO.select for efficient non-blocking polling
        ready_sockets = IO.select(sockets, nil, nil, @select_timeout)
        
        # Handle ready sockets if any
        if ready_sockets && ready_sockets[0]
          ready_sockets[0].each do |socket|
            process_socket(socket)
          end
        end
        
        # Yield control to allow other threads to run
        Thread.pass if @stats[:loop_iterations] % 100 == 0
      end
    end

    # Process packets from a ready socket
    def process_socket(socket)
      # Find interface by socket
      interface = @interfaces.values.find { |iface| iface.socket == socket }
      return unless interface

      begin
        # Read packet with timestamp
        packet_data = interface.read_packet(@max_packet_size)
        return unless packet_data
        
        timestamp = Time.now
        
        # Update statistics
        @stats[:packets_received] += 1
        @stats[:bytes_received] += packet_data.bytesize
        
        # Process packet through handlers
        process_packet(interface.name, packet_data, timestamp)
        
      rescue NetworkError => e
        handle_error(e, interface: interface.name)
      rescue => e
        # Unexpected error - log and continue
        handle_error(e, interface: interface.name, unexpected: true)
      end
    end

    # Dispatch packet to registered handlers
    def process_packet(interface_name, packet_data, timestamp)
      @packet_handlers.each do |handler|
        begin
          handler.call(interface_name, packet_data, timestamp)
        rescue => e
          handle_error(e, context: :packet_handler)
        end
      end
    end

    # Handle errors through registered handlers
    def handle_error(error, context = {})
      @error_handlers.each do |handler|
        begin
          handler.call(error, context)
        rescue => e
          # Error in error handler - log to stderr as last resort
          $stderr.puts "Error in error handler: #{e.class}: #{e.message}"
        end
      end
    end

    # Clean up reactor state and interfaces
    def cleanup_reactor
      @state = STOPPING
      
      # Close all interfaces
      @interfaces.each_value do |interface|
        begin
          interface.close
        rescue => e
          handle_error(e, context: :cleanup)
        end
      end
      
      @interfaces.clear
      @state = STOPPED
    end
  end
end
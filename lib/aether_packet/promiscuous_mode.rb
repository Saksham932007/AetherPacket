# frozen_string_literal: true

require "fiddle"

module AetherPacket
  # PromiscuousMode manages interface promiscuous mode state
  # Enables capturing all network traffic, not just frames destined for this host
  class PromiscuousMode
    # Linux ioctl constants for interface flags manipulation
    SIOCGIFFLAGS = 0x8913  # Get interface flags
    SIOCSIFFLAGS = 0x8914  # Set interface flags
    
    # Interface flag constants
    IFF_PROMISC = 0x0100   # Promiscuous mode enabled
    IFF_UP = 0x0001        # Interface is administratively up
    IFF_RUNNING = 0x0040   # Interface is operationally up

    attr_reader :interface_name, :original_flags

    def initialize(interface_name, socket)
      @interface_name = interface_name
      @socket = socket
      @original_flags = nil
      @promisc_enabled = false
    end

    # Enable promiscuous mode on the interface
    def enable!
      return if @promisc_enabled
      
      current_flags = get_interface_flags
      @original_flags = current_flags
      
      # Check if already in promiscuous mode
      if (current_flags & IFF_PROMISC) != 0
        @promisc_enabled = true
        return true
      end

      # Set promiscuous flag
      new_flags = current_flags | IFF_PROMISC
      set_interface_flags(new_flags)
      
      @promisc_enabled = true
      verify_promiscuous_mode!
      
      true
    rescue SystemCallError => e
      raise SystemError, "Failed to enable promiscuous mode: #{e.message}. Check permissions."
    end

    # Disable promiscuous mode and restore original flags
    def disable!
      return unless @promisc_enabled && @original_flags
      
      current_flags = get_interface_flags
      
      # Only clear promiscuous flag if we originally enabled it
      if (@original_flags & IFF_PROMISC) == 0
        new_flags = current_flags & ~IFF_PROMISC
        set_interface_flags(new_flags)
      end
      
      @promisc_enabled = false
      true
    rescue SystemCallError => e
      raise SystemError, "Failed to disable promiscuous mode: #{e.message}"
    end

    # Check if promiscuous mode is currently enabled
    def enabled?
      return @promisc_enabled if @promisc_enabled
      
      current_flags = get_interface_flags
      (current_flags & IFF_PROMISC) != 0
    end

    # Get current interface operational state
    def interface_state
      flags = get_interface_flags
      {
        up: (flags & IFF_UP) != 0,
        running: (flags & IFF_RUNNING) != 0, 
        promiscuous: (flags & IFF_PROMISC) != 0
      }
    end

    private

    # Get current interface flags using ioctl
    def get_interface_flags
      # Create ifreq structure: char name[16], short flags, padding
      ifreq = [@interface_name].pack("a16")
      
      # SIOCGIFFLAGS returns the current interface flags
      result = @socket.ioctl(SIOCGIFFLAGS, ifreq)
      
      # Unpack the flags from the result (16 bytes name + 2 bytes flags)  
      result.unpack("a16n")[1]
    rescue SystemCallError => e
      raise InterfaceError, "Failed to get interface flags: #{e.message}"
    end

    # Set interface flags using ioctl
    def set_interface_flags(flags)
      # Create ifreq structure with new flags
      ifreq = [@interface_name, flags].pack("a16n")
      
      # SIOCSIFFLAGS sets the interface flags
      @socket.ioctl(SIOCSIFFLAGS, ifreq)
    rescue SystemCallError => e
      raise InterfaceError, "Failed to set interface flags: #{e.message}"
    end

    # Verify that promiscuous mode was actually enabled
    def verify_promiscuous_mode!
      current_flags = get_interface_flags
      unless (current_flags & IFF_PROMISC) != 0
        raise SystemError, "Promiscuous mode verification failed"
      end
    end
  end

  # Add promiscuous mode support to NetworkInterface
  class NetworkInterface
    attr_reader :promiscuous_mode

    # Initialize promiscuous mode after socket creation
    alias_method :original_initialize, :initialize
    
    def initialize(interface_name)
      original_initialize(interface_name)
      @promiscuous_mode = PromiscuousMode.new(@name, @socket)
    end

    # Enable promiscuous mode for full traffic capture
    def enable_promiscuous!
      @promiscuous_mode.enable!
    end

    # Disable promiscuous mode
    def disable_promiscuous!
      @promiscuous_mode.disable!
    end

    # Check if promiscuous mode is enabled
    def promiscuous?
      @promiscuous_mode.enabled?
    end

    # Enhanced close method to restore interface state
    alias_method :original_close, :close
    
    def close
      @promiscuous_mode&.disable!
      original_close
    end
  end
end
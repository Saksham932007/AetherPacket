# frozen_string_literal: true

require "socket"
require "fiddle"

module AetherPacket
  # NetworkInterface manages raw PF_PACKET socket operations
  # Provides direct wire-level access to network traffic
  class NetworkInterface
    # Linux network interface ioctl constants
    SIOCGIFINDEX = 0x8933  # Get interface index
    SIOCGIFHWADDR = 0x8927 # Get hardware address
    SIOCGIFFLAGS = 0x8913  # Get interface flags
    SIOCSIFFLAGS = 0x8914  # Set interface flags
    
    # Interface flags
    IFF_PROMISC = 0x0100   # Promiscuous mode
    IFF_UP = 0x0001        # Interface is up
    IFF_RUNNING = 0x0040   # Interface is running
    
    attr_reader :name, :index, :mac_address, :socket

    def initialize(interface_name)
      @name = interface_name
      @socket = nil
      @index = nil
      @mac_address = nil
      
      validate_interface!
      create_raw_socket!
      bind_to_interface!
    end

    # Bind socket to specific network interface
    def bind_to_interface!
      # Create sockaddr_ll structure for PF_PACKET binding
      # struct sockaddr_ll {
      #   unsigned short sll_family;   // Always AF_PACKET
      #   unsigned short sll_protocol; // Physical layer protocol  
      #   int sll_ifindex;             // Interface number
      #   unsigned short sll_hatype;   // ARP hardware type
      #   unsigned char sll_pkttype;   // Packet type
      #   unsigned char sll_halen;     // Length of address
      #   unsigned char sll_addr[8];   // Physical layer address
      # };
      
      sockaddr_ll = [
        Socket::AF_PACKET,  # sll_family
        0x0300,            # sll_protocol (ETH_P_ALL in network byte order)
        @index,            # sll_ifindex
        0,                 # sll_hatype
        0,                 # sll_pkttype  
        0,                 # sll_halen
        0, 0               # sll_addr padding
      ].pack("nnNnCCQ")
      
      @socket.bind(sockaddr_ll)
    rescue SystemCallError => e
      raise SocketError, "Failed to bind to interface #{@name}: #{e.message}"
    end

    # Read raw packet data from the socket
    def read_packet(max_size = 65536)
      @socket.recvfrom(max_size)[0]
    rescue IO::WaitReadable
      nil
    rescue SystemCallError => e
      raise NetworkError, "Failed to read packet: #{e.message}"
    end

    # Write raw packet data to the socket  
    def write_packet(data)
      bytes_sent = @socket.send(data, 0)
      raise NetworkError, "Partial write: #{bytes_sent}/#{data.bytesize}" if bytes_sent != data.bytesize
      bytes_sent
    rescue SystemCallError => e
      raise NetworkError, "Failed to write packet: #{e.message}"
    end

    # Check if interface is ready for non-blocking operations
    def ready_for_read?(timeout = 0)
      IO.select([@socket], nil, nil, timeout) ? true : false
    end

    # Close the raw socket
    def close
      @socket&.close
      @socket = nil
    end

    private

    def validate_interface!
      raise InterfaceError, "Interface name cannot be empty" if @name.nil? || @name.empty?
      raise InterfaceError, "Interface name too long" if @name.bytesize > 15
      
      get_interface_index!
      get_mac_address!
    end

    def create_raw_socket!
      # Create AF_PACKET socket with SOCK_RAW for direct Ethernet frame access
      # ETH_P_ALL (0x0003) captures all protocols
      @socket = Socket.new(Socket::AF_PACKET, Socket::SOCK_RAW, 0x0300)
      @socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
      
      # Enable non-blocking mode for high-performance polling
      @socket.fcntl(Fcntl::F_SETFL, Fcntl::O_NONBLOCK)
    rescue SystemCallError => e
      raise SocketError, "Failed to create raw socket: #{e.message}. Are you running as root?"
    end

    def get_interface_index!
      # Use ioctl to get interface index from kernel
      ifreq_struct = [@name].pack("a16")
      result = @socket.ioctl(SIOCGIFINDEX, ifreq_struct)
      @index = result.unpack("a16N")[1]
      raise InterfaceError, "Interface #{@name} not found" if @index.zero?
    rescue SystemCallError => e
      raise InterfaceError, "Failed to get interface index: #{e.message}"
    end

    def get_mac_address!
      # Get hardware address using ioctl
      ifreq_struct = [@name].pack("a16")
      result = @socket.ioctl(SIOCGIFHWADDR, ifreq_struct)
      # Extract MAC address from result (skip family bytes)
      mac_bytes = result.unpack("a16nC6")[2..7]
      @mac_address = mac_bytes.map { |b| format("%02x", b) }.join(":")
    rescue SystemCallError => e
      raise InterfaceError, "Failed to get MAC address: #{e.message}"
    end
  end
end
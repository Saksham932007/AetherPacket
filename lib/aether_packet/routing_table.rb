# frozen_string_literal: true

module AetherPacket
  # RoutingTable implements Longest Prefix Matching using a Radix Tree (Trie)
  # Provides O(log n) route lookup performance for enterprise-grade routing
  class RoutingTable
    # Route entry structure
    Route = Struct.new(:network, :prefix_length, :gateway, :interface, :metric, :created_at) do
      def to_s
        "#{network}/#{prefix_length} via #{gateway} dev #{interface} metric #{metric}"
      end

      def network_int
        @network_int ||= RoutingTable.ip_string_to_int(network)
      end

      def netmask
        @netmask ||= (0xffffffff << (32 - prefix_length)) & 0xffffffff
      end

      def contains_ip?(ip_string)
        ip_int = RoutingTable.ip_string_to_int(ip_string)
        (ip_int & netmask) == (network_int & netmask)
      end
    end

    # Radix Tree Node for efficient prefix matching
    class RadixNode
      attr_accessor :route, :children, :prefix, :prefix_length

      def initialize(prefix = 0, prefix_length = 0)
        @prefix = prefix
        @prefix_length = prefix_length
        @route = nil
        @children = {}  # bit -> node
      end

      def leaf?
        @children.empty?
      end

      def has_route?
        !@route.nil?
      end
    end

    attr_reader :root, :routes_count

    def initialize
      @root = RadixNode.new
      @routes_count = 0
    end

    # Add route to the routing table
    def add_route(network, prefix_length, gateway: nil, interface:, metric: 0)
      raise ArgumentError, "Invalid prefix length" unless prefix_length >= 0 && prefix_length <= 32
      
      route = Route.new(
        normalize_network(network, prefix_length),
        prefix_length,
        gateway,
        interface,
        metric,
        Time.now
      )

      insert_route(route)
      @routes_count += 1
      route
    end

    # Remove route from the routing table
    def remove_route(network, prefix_length)
      network = normalize_network(network, prefix_length)
      network_int = self.class.ip_string_to_int(network)
      
      removed = remove_route_from_tree(@root, network_int, prefix_length, 0)
      @routes_count -= 1 if removed
      removed
    end

    # Lookup route for destination IP (Longest Prefix Match)
    def lookup(destination_ip)
      destination_int = self.class.ip_string_to_int(destination_ip)
      longest_match_route(@root, destination_int, 0)
    end

    # Get all routes sorted by prefix length (most specific first)
    def all_routes
      routes = []
      collect_routes(@root, routes)
      routes.sort_by { |r| [-r.prefix_length, r.metric, r.network] }
    end

    # Get routes for specific interface
    def routes_for_interface(interface)
      all_routes.select { |route| route.interface == interface }
    end

    # Get default route (0.0.0.0/0)
    def default_route
      all_routes.find { |route| route.prefix_length == 0 }
    end

    # Clear all routes
    def clear!
      @root = RadixNode.new
      @routes_count = 0
    end

    # Get routing table statistics
    def stats
      {
        total_routes: @routes_count,
        tree_depth: calculate_tree_depth(@root),
        default_routes: all_routes.count { |r| r.prefix_length == 0 },
        host_routes: all_routes.count { |r| r.prefix_length == 32 },
        interfaces: all_routes.map(&:interface).uniq.sort
      }
    end

    # Export routes in standard format
    def export_routes
      all_routes.map do |route|
        {
          destination: "#{route.network}/#{route.prefix_length}",
          gateway: route.gateway || "0.0.0.0",
          interface: route.interface,
          metric: route.metric,
          created_at: route.created_at.iso8601
        }
      end
    end

    # Convert IP string to 32-bit integer
    def self.ip_string_to_int(ip_string)
      octets = ip_string.split(".").map(&:to_i)
      raise ArgumentError, "Invalid IP address: #{ip_string}" unless valid_ip_octets?(octets)
      
      (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
    end

    # Convert 32-bit integer to IP string
    def self.int_to_ip_string(ip_int)
      [(ip_int >> 24) & 0xff, (ip_int >> 16) & 0xff, (ip_int >> 8) & 0xff, ip_int & 0xff].join(".")
    end

    private

    # Insert route into radix tree
    def insert_route(route)
      network_int = route.network_int
      current_node = @root
      
      route.prefix_length.times do |bit_position|
        bit = (network_int >> (31 - bit_position)) & 1
        
        current_node.children[bit] ||= RadixNode.new(
          network_int & (0xffffffff << (31 - bit_position)),
          bit_position + 1
        )
        
        current_node = current_node.children[bit]
      end
      
      # Replace existing route or add new one
      current_node.route = route
    end

    # Remove route from radix tree
    def remove_route_from_tree(node, network_int, prefix_length, depth)
      return nil if depth > prefix_length
      
      if depth == prefix_length
        removed_route = node.route
        node.route = nil
        return removed_route
      end
      
      bit = (network_int >> (31 - depth)) & 1
      child_node = node.children[bit]
      return nil unless child_node
      
      removed_route = remove_route_from_tree(child_node, network_int, prefix_length, depth + 1)
      
      # Clean up empty nodes
      if !child_node.has_route? && child_node.leaf?
        node.children.delete(bit)
      end
      
      removed_route
    end

    # Find longest matching route in tree
    def longest_match_route(node, destination_int, depth)
      # Current node has a route - this is a potential match
      best_match = node.route
      
      # Continue searching more specific routes
      if depth < 32
        bit = (destination_int >> (31 - depth)) & 1
        child_node = node.children[bit]
        
        if child_node
          child_match = longest_match_route(child_node, destination_int, depth + 1)
          best_match = child_match if child_match
        end
      end
      
      best_match
    end

    # Collect all routes from tree
    def collect_routes(node, routes)
      routes << node.route if node.has_route?
      
      node.children.each_value do |child|
        collect_routes(child, routes)
      end
    end

    # Calculate maximum tree depth
    def calculate_tree_depth(node, current_depth = 0)
      return current_depth if node.leaf?
      
      max_child_depth = node.children.values.map do |child|
        calculate_tree_depth(child, current_depth + 1)
      end.max || current_depth
      
      max_child_depth
    end

    # Normalize network address for given prefix
    def normalize_network(network, prefix_length)
      network_int = self.class.ip_string_to_int(network)
      netmask = (0xffffffff << (32 - prefix_length)) & 0xffffffff
      normalized_int = network_int & netmask
      self.class.int_to_ip_string(normalized_int)
    end

    # Validate IP address octets
    def self.valid_ip_octets?(octets)
      octets.length == 4 && octets.all? { |o| o >= 0 && o <= 255 }
    end
  end
end
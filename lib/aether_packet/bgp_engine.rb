# frozen_string_literal: true

module AetherPacket
  # BgpMessage represents BGP protocol messages
  class BgpMessage
    attr_reader :type, :length, :data

    MESSAGE_TYPES = {
      1 => :open,
      2 => :update,
      3 => :notification,
      4 => :keepalive,
      5 => :route_refresh
    }.freeze

    def initialize(type, data = '')
      @type = type
      @data = data
      @length = 19 + data.bytesize  # BGP header is 19 bytes
    end

    # Parse BGP message from binary data
    def self.parse(binary_data)
      return nil if binary_data.bytesize < 19
      
      marker = binary_data[0..15]
      return nil unless marker == "\xFF" * 16  # BGP marker
      
      length = binary_data[16..17].unpack1('n')
      type = binary_data[18].ord
      data = binary_data[19...length]
      
      new(type, data)
    end

    # Convert to binary representation
    def to_binary
      header = "\xFF" * 16  # Marker
      header += [@length].pack('n')  # Length
      header += [@type].pack('C')    # Type
      header + @data
    end

    def message_type_name
      MESSAGE_TYPES[@type] || :unknown
    end
  end

  # BgpPathAttributes represents BGP path attributes
  class BgpPathAttributes
    attr_accessor :origin, :as_path, :next_hop, :med, :local_pref, :communities

    def initialize
      @origin = :igp
      @as_path = []
      @next_hop = nil
      @med = nil
      @local_pref = 100
      @communities = []
    end

    # Parse path attributes from binary data
    def self.parse(binary_data)
      attributes = new
      offset = 0
      
      while offset < binary_data.bytesize
        flags = binary_data[offset].ord
        type_code = binary_data[offset + 1].ord
        
        # Length can be 1 or 2 bytes depending on extended length flag
        if (flags & 0x10) != 0  # Extended length
          length = binary_data[offset + 2..offset + 3].unpack1('n')
          value_offset = offset + 4
        else
          length = binary_data[offset + 2].ord
          value_offset = offset + 3
        end
        
        value_data = binary_data[value_offset...value_offset + length]
        
        case type_code
        when 1  # ORIGIN
          attributes.origin = [:igp, :egp, :incomplete][value_data.ord] || :unknown
        when 2  # AS_PATH
          attributes.as_path = parse_as_path(value_data)
        when 3  # NEXT_HOP
          attributes.next_hop = value_data.unpack('C4').join('.')
        when 4  # MULTI_EXIT_DISC
          attributes.med = value_data.unpack1('N')
        when 5  # LOCAL_PREF
          attributes.local_pref = value_data.unpack1('N')
        when 8  # COMMUNITIES
          attributes.communities = parse_communities(value_data)
        end
        
        offset = value_offset + length
      end
      
      attributes
    end

    # Convert to binary representation
    def to_binary
      binary_data = ""
      
      # ORIGIN
      binary_data += build_attribute(1, [@origin_value].pack('C'))
      
      # AS_PATH
      binary_data += build_attribute(2, build_as_path)
      
      # NEXT_HOP
      if @next_hop
        ip_bytes = @next_hop.split('.').map(&:to_i).pack('C4')
        binary_data += build_attribute(3, ip_bytes)
      end
      
      # LOCAL_PREF
      binary_data += build_attribute(5, [@local_pref].pack('N'))
      
      # MED
      if @med
        binary_data += build_attribute(4, [@med].pack('N'))
      end
      
      # COMMUNITIES
      if @communities.any?
        comm_data = @communities.map { |c| [c].pack('N') }.join
        binary_data += build_attribute(8, comm_data)
      end
      
      binary_data
    end

    private

    def self.parse_as_path(data)
      as_path = []
      offset = 0
      
      while offset < data.bytesize
        segment_type = data[offset].ord
        segment_length = data[offset + 1].ord
        
        segment_as_numbers = []
        (0...segment_length).each do |i|
          as_number = data[offset + 2 + (i * 2)..offset + 3 + (i * 2)].unpack1('n')
          segment_as_numbers << as_number
        end
        
        as_path.concat(segment_as_numbers)
        offset += 2 + (segment_length * 2)
      end
      
      as_path
    end

    def self.parse_communities(data)
      communities = []
      (0...data.bytesize).step(4) do |i|
        community = data[i..i+3].unpack1('N')
        communities << community
      end
      communities
    end

    def origin_value
      case @origin
      when :igp then 0
      when :egp then 1
      when :incomplete then 2
      else 0
      end
    end

    def build_attribute(type_code, value)
      flags = 0x40  # Well-known mandatory
      flags |= 0x10 if value.bytesize > 255  # Extended length
      
      attr_data = [flags, type_code].pack('CC')
      
      if (flags & 0x10) != 0
        attr_data += [value.bytesize].pack('n')
      else
        attr_data += [value.bytesize].pack('C')
      end
      
      attr_data + value
    end

    def build_as_path
      return "" if @as_path.empty?
      
      # AS_SEQUENCE segment
      segment_data = [2].pack('C')  # AS_SEQUENCE
      segment_data += [@as_path.size].pack('C')
      segment_data += @as_path.map { |as_num| [as_num].pack('n') }.join
      
      segment_data
    end
  end

  # BgpPeer represents a BGP peering session
  class BgpPeer
    attr_reader :peer_ip, :peer_as, :state, :session_stats

    STATES = [:idle, :connect, :active, :opensent, :openconfirm, :established].freeze

    def initialize(peer_ip, peer_as, local_as, local_ip)
      @peer_ip = peer_ip
      @peer_as = peer_as
      @local_as = local_as
      @local_ip = local_ip
      @state = :idle
      @hold_time = 180
      @keepalive_time = 60
      @last_keepalive = Time.now
      @last_update = Time.now
      
      @session_stats = {
        session_established_time: nil,
        updates_received: 0,
        updates_sent: 0,
        keepalives_received: 0,
        keepalives_sent: 0,
        notifications_received: 0,
        notifications_sent: 0,
        prefixes_received: 0,
        prefixes_advertised: 0
      }
    end

    # Establish BGP session
    def establish_session
      return false unless @state == :idle
      
      @state = :connect
      send_open_message
      @state = :opensent
      
      # Simulate session establishment
      @state = :openconfirm
      @state = :established
      @session_stats[:session_established_time] = Time.now
      
      puts "BGP session established with #{@peer_ip} (AS#{@peer_as})"
      true
    end

    # Send BGP UPDATE message
    def send_update(nlri_prefixes, withdrawn_routes = [], path_attributes = nil)
      return false unless @state == :established
      
      update_data = build_update_message(nlri_prefixes, withdrawn_routes, path_attributes)
      message = BgpMessage.new(2, update_data)  # UPDATE type
      
      # Simulate sending message
      @session_stats[:updates_sent] += 1
      @session_stats[:prefixes_advertised] += nlri_prefixes.size
      
      true
    end

    # Process received BGP message
    def process_message(message)
      case message.message_type_name
      when :open
        process_open_message(message)
      when :update
        process_update_message(message)
      when :keepalive
        process_keepalive_message(message)
      when :notification
        process_notification_message(message)
      end
    end

    # Send keepalive message
    def send_keepalive
      return false unless @state == :established
      
      message = BgpMessage.new(4)  # KEEPALIVE type
      @session_stats[:keepalives_sent] += 1
      @last_keepalive = Time.now
      
      true
    end

    # Check if session needs keepalive
    def needs_keepalive?
      Time.now - @last_keepalive > @keepalive_time
    end

    # Check if session has timed out
    def session_timeout?
      @state == :established && Time.now - @last_update > @hold_time
    end

    # Tear down session
    def teardown_session(error_code = 6, error_subcode = 0)
      notification_data = [error_code, error_subcode].pack('CC')
      message = BgpMessage.new(3, notification_data)  # NOTIFICATION type
      
      @session_stats[:notifications_sent] += 1
      @state = :idle
      
      puts "BGP session with #{@peer_ip} torn down"
    end

    # Get session uptime
    def session_uptime
      return 0 unless @session_stats[:session_established_time]
      Time.now - @session_stats[:session_established_time]
    end

    private

    def send_open_message
      # BGP OPEN message parameters
      version = 4
      hold_time = @hold_time
      bgp_identifier = @local_ip.split('.').map(&:to_i).pack('C4').unpack1('N')
      
      open_data = [version].pack('C')
      open_data += [@local_as].pack('n')
      open_data += [hold_time].pack('n')
      open_data += [bgp_identifier].pack('N')
      open_data += [0].pack('C')  # Optional parameters length
      
      message = BgpMessage.new(1, open_data)  # OPEN type
      true
    end

    def build_update_message(nlri_prefixes, withdrawn_routes, path_attributes)
      update_data = ""
      
      # Withdrawn Routes Length
      withdrawn_data = withdrawn_routes.map { |route| encode_prefix(route) }.join
      update_data += [withdrawn_data.bytesize].pack('n')
      update_data += withdrawn_data
      
      # Total Path Attribute Length
      path_attr_data = path_attributes ? path_attributes.to_binary : ""
      update_data += [path_attr_data.bytesize].pack('n')
      update_data += path_attr_data
      
      # NLRI
      nlri_data = nlri_prefixes.map { |prefix| encode_prefix(prefix) }.join
      update_data += nlri_data
      
      update_data
    end

    def encode_prefix(prefix)
      network, prefix_length = prefix.split('/')
      prefix_length = prefix_length.to_i
      
      # Calculate number of bytes needed for prefix
      byte_length = (prefix_length + 7) / 8
      
      # Convert IP to bytes and truncate to needed length
      ip_bytes = network.split('.').map(&:to_i).pack('C4')
      
      [prefix_length].pack('C') + ip_bytes[0...byte_length]
    end

    def process_open_message(message)
      # Parse OPEN message and validate parameters
      @state = :openconfirm if @state == :opensent
    end

    def process_update_message(message)
      @session_stats[:updates_received] += 1
      @last_update = Time.now
      
      # Parse UPDATE message and extract NLRI, path attributes
      # This would update the RIB (Routing Information Base)
    end

    def process_keepalive_message(message)
      @session_stats[:keepalives_received] += 1
      @last_update = Time.now
      
      # Confirm session is alive
      @state = :established if @state == :openconfirm
    end

    def process_notification_message(message)
      @session_stats[:notifications_received] += 1
      @state = :idle
      
      puts "BGP NOTIFICATION received from #{@peer_ip}"
    end
  end

  # BgpEngine implements BGP-4 routing protocol
  class BgpEngine
    attr_reader :local_as, :router_id, :peers, :rib, :stats

    def initialize(local_as, router_id)
      @local_as = local_as
      @router_id = router_id
      @peers = {}
      @rib = {}  # Routing Information Base
      @adj_rib_in = {}  # Adj-RIB-In per peer
      @adj_rib_out = {}  # Adj-RIB-Out per peer
      @loc_rib = {}  # Loc-RIB (selected routes)
      
      @stats = {
        peers_configured: 0,
        peers_established: 0,
        total_prefixes: 0,
        best_paths: 0,
        updates_processed: 0
      }
      
      @running = false
      start_bgp_process
    end

    # Add BGP peer
    def add_peer(peer_ip, peer_as, **options)
      return false if @peers[peer_ip]
      
      peer = BgpPeer.new(peer_ip, peer_as, @local_as, @router_id)
      @peers[peer_ip] = peer
      @adj_rib_in[peer_ip] = {}
      @adj_rib_out[peer_ip] = {}
      
      @stats[:peers_configured] += 1
      
      puts "Added BGP peer #{peer_ip} (AS#{peer_as})"
      true
    end

    # Remove BGP peer
    def remove_peer(peer_ip)
      peer = @peers.delete(peer_ip)
      return false unless peer
      
      peer.teardown_session
      @adj_rib_in.delete(peer_ip)
      @adj_rib_out.delete(peer_ip)
      
      @stats[:peers_configured] -= 1
      @stats[:peers_established] -= 1 if peer.state == :established
      
      # Withdraw routes learned from this peer
      withdraw_peer_routes(peer_ip)
      
      true
    end

    # Establish session with peer
    def establish_session(peer_ip)
      peer = @peers[peer_ip]
      return false unless peer
      
      if peer.establish_session
        @stats[:peers_established] += 1
        true
      else
        false
      end
    end

    # Advertise prefix to peers
    def advertise_prefix(prefix, next_hop, **attributes)
      path_attrs = BgpPathAttributes.new
      path_attrs.next_hop = next_hop
      path_attrs.as_path = [@local_as]
      path_attrs.origin = attributes[:origin] || :igp
      path_attrs.med = attributes[:med]
      path_attrs.local_pref = attributes[:local_pref] || 100
      
      # Add to Loc-RIB
      @loc_rib[prefix] = {
        next_hop: next_hop,
        path_attributes: path_attrs,
        origin: :local
      }
      
      # Advertise to established peers
      @peers.each do |peer_ip, peer|
        next unless peer.state == :established
        
        # Apply export policy (simplified)
        if should_advertise_to_peer(prefix, peer_ip)
          peer.send_update([prefix], [], path_attrs)
          @adj_rib_out[peer_ip][prefix] = path_attrs
        end
      end
      
      @stats[:total_prefixes] += 1
      @stats[:best_paths] += 1
      
      true
    end

    # Withdraw prefix advertisement
    def withdraw_prefix(prefix)
      return false unless @loc_rib[prefix]
      
      @loc_rib.delete(prefix)
      
      # Send withdrawal to all peers
      @peers.each do |peer_ip, peer|
        next unless peer.state == :established
        
        peer.send_update([], [prefix])
        @adj_rib_out[peer_ip].delete(prefix)
      end
      
      @stats[:total_prefixes] -= 1
      @stats[:best_paths] -= 1
      
      true
    end

    # Process BGP UPDATE from peer
    def process_update(peer_ip, nlri_prefixes, withdrawn_routes, path_attributes)
      return false unless @peers[peer_ip]&.state == :established
      
      @stats[:updates_processed] += 1
      
      # Process withdrawals
      withdrawn_routes.each do |prefix|
        @adj_rib_in[peer_ip].delete(prefix)
        run_best_path_selection(prefix)
      end
      
      # Process new/updated prefixes
      nlri_prefixes.each do |prefix|
        @adj_rib_in[peer_ip][prefix] = path_attributes
        run_best_path_selection(prefix)
      end
      
      true
    end

    # Get BGP table for prefix
    def bgp_table(prefix = nil)
      if prefix
        routes = {}
        @adj_rib_in.each do |peer_ip, rib|
          routes[peer_ip] = rib[prefix] if rib[prefix]
        end
        routes[@router_id] = @loc_rib[prefix] if @loc_rib[prefix]
        routes
      else
        # Return all prefixes
        all_prefixes = Set.new
        @adj_rib_in.each_value { |rib| all_prefixes.merge(rib.keys) }
        all_prefixes.merge(@loc_rib.keys)
        
        all_prefixes.to_h do |pfx|
          [pfx, bgp_table(pfx)]
        end
      end
    end

    # Get BGP summary
    def bgp_summary
      peer_summary = @peers.transform_values do |peer|
        {
          state: peer.state,
          uptime: peer.session_uptime,
          prefixes_received: peer.session_stats[:prefixes_received],
          prefixes_advertised: peer.session_stats[:prefixes_advertised]
        }
      end
      
      {
        local_as: @local_as,
        router_id: @router_id,
        peers: peer_summary,
        statistics: @stats,
        table_size: @loc_rib.size + @adj_rib_in.values.sum(&:size)
      }
    end

    # Start BGP processing
    def start!
      @running = true
      puts "BGP Engine started (AS#{@local_as}, Router-ID: #{@router_id})"
    end

    # Stop BGP processing
    def stop!
      @running = false
      
      # Tear down all sessions
      @peers.each_value(&:teardown_session)
      
      puts "BGP Engine stopped"
    end

    private

    def start_bgp_process
      Thread.new do
        Thread.current.name = "bgp-engine"
        
        while @running
          # BGP keepalive and timeout processing
          @peers.each do |peer_ip, peer|
            next unless peer.state == :established
            
            if peer.needs_keepalive?
              peer.send_keepalive
            end
            
            if peer.session_timeout?
              puts "BGP session timeout for #{peer_ip}"
              peer.teardown_session
              @stats[:peers_established] -= 1
            end
          end
          
          sleep(30)  # Check every 30 seconds
        end
      end
    end

    def run_best_path_selection(prefix)
      candidates = []
      
      # Collect all available paths for this prefix
      @adj_rib_in.each do |peer_ip, rib|
        if rib[prefix]
          candidates << {
            peer: peer_ip,
            path_attributes: rib[prefix],
            source: :ibgp_ebgp
          }
        end
      end
      
      # Add local route if exists
      if @loc_rib[prefix]
        candidates << {
          peer: @router_id,
          path_attributes: @loc_rib[prefix][:path_attributes],
          source: :local
        }
      end
      
      # BGP best path selection algorithm
      best_path = select_best_path(candidates)
      
      if best_path
        # Install in Loc-RIB
        @loc_rib[prefix] = best_path
        
        # Advertise to peers if needed
        propagate_best_path(prefix, best_path)
      else
        # No valid path - remove from Loc-RIB
        @loc_rib.delete(prefix)
      end
    end

    def select_best_path(candidates)
      return nil if candidates.empty?
      return candidates.first if candidates.size == 1
      
      # Simplified best path selection (RFC 4271)
      # 1. Prefer local routes
      local_routes = candidates.select { |c| c[:source] == :local }
      return local_routes.first unless local_routes.empty?
      
      # 2. Prefer highest local preference
      candidates.sort_by! { |c| -c[:path_attributes].local_pref }
      max_local_pref = candidates.first[:path_attributes].local_pref
      candidates.select! { |c| c[:path_attributes].local_pref == max_local_pref }
      
      # 3. Prefer shortest AS path
      candidates.sort_by! { |c| c[:path_attributes].as_path.size }
      min_as_path_length = candidates.first[:path_attributes].as_path.size
      candidates.select! { |c| c[:path_attributes].as_path.size == min_as_path_length }
      
      # 4. Prefer lowest origin type (IGP < EGP < Incomplete)
      origin_preference = { igp: 0, egp: 1, incomplete: 2 }
      candidates.sort_by! { |c| origin_preference[c[:path_attributes].origin] || 999 }
      
      # Return best path
      candidates.first
    end

    def propagate_best_path(prefix, best_path)
      # Advertise to peers based on BGP route propagation rules
      @peers.each do |peer_ip, peer|
        next unless peer.state == :established
        next if peer_ip == best_path[:peer]  # Don't advertise back to originator
        
        if should_advertise_to_peer(prefix, peer_ip)
          peer.send_update([prefix], [], best_path[:path_attributes])
          @adj_rib_out[peer_ip][prefix] = best_path[:path_attributes]
        end
      end
    end

    def should_advertise_to_peer(prefix, peer_ip)
      # Simplified export policy
      # In real BGP, this would check route maps, filters, etc.
      true
    end

    def withdraw_peer_routes(peer_ip)
      # Remove all routes learned from this peer
      prefixes_to_update = @adj_rib_in[peer_ip]&.keys || []
      
      prefixes_to_update.each do |prefix|
        @adj_rib_in[peer_ip].delete(prefix)
        run_best_path_selection(prefix)
      end
    end
  end
end
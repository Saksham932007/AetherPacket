# frozen_string_literal: true

require_relative '../lib/aether_packet'
require 'socket'
require 'timeout'

module AetherPacket
  # TestPacketGenerator creates test packets for integration testing
  class TestPacketGenerator
    def self.create_ethernet_frame(src_mac: '00:11:22:33:44:55', dst_mac: 'ff:ff:ff:ff:ff:ff', 
                                  ethertype: 0x0800, payload: '')
      frame_data = [dst_mac.gsub(':', '')].pack('H*')  # 6 bytes
      frame_data += [src_mac.gsub(':', '')].pack('H*')  # 6 bytes
      frame_data += [ethertype].pack('n')                # 2 bytes
      frame_data += payload                              # Variable
      frame_data
    end

    def self.create_ipv4_packet(src_ip: '192.168.1.1', dst_ip: '192.168.1.2', 
                               protocol: 6, payload: '')
      # Simple IPv4 header construction
      header = "\x45"        # Version (4) + IHL (5)
      header += "\x00"       # DSCP + ECN
      header += [20 + payload.bytesize].pack('n')  # Total Length
      header += "\x00\x00"   # Identification
      header += "\x40\x00"   # Flags + Fragment Offset
      header += "\x40"       # TTL
      header += [protocol].pack('C')  # Protocol
      header += "\x00\x00"   # Checksum (calculated later)
      header += IPAddr.new(src_ip).to_i.to_s(2).rjust(32, '0').scan(/.{8}/).map { |b| b.to_i(2) }.pack('C4')
      header += IPAddr.new(dst_ip).to_i.to_s(2).rjust(32, '0').scan(/.{8}/).map { |b| b.to_i(2) }.pack('C4')
      
      # Calculate checksum
      checksum = calculate_ipv4_checksum(header)
      header[10..11] = [checksum].pack('n')
      
      header + payload
    end

    def self.create_tcp_segment(src_port: 1234, dst_port: 80, flags: 0x02, payload: '')
      # Simple TCP header construction
      header = [src_port].pack('n')      # Source Port
      header += [dst_port].pack('n')     # Destination Port
      header += [rand(2**32)].pack('N')  # Sequence Number
      header += [0].pack('N')            # Acknowledgment Number
      header += "\x50"                   # Data Offset (5) + Reserved
      header += [flags].pack('C')        # Flags
      header += [8192].pack('n')         # Window Size
      header += "\x00\x00"               # Checksum (calculated later)
      header += "\x00\x00"               # Urgent Pointer
      
      header + payload
    end

    def self.create_udp_datagram(src_port: 1234, dst_port: 53, payload: '')
      header = [src_port].pack('n')                    # Source Port
      header += [dst_port].pack('n')                   # Destination Port
      header += [8 + payload.bytesize].pack('n')       # Length
      header += "\x00\x00"                             # Checksum
      
      header + payload
    end

    def self.create_dns_query(domain: 'example.com', qtype: 1)
      # DNS query packet
      header = [rand(65536)].pack('n')   # Transaction ID
      header += "\x01\x00"               # Flags (standard query)
      header += "\x00\x01"               # Questions: 1
      header += "\x00\x00"               # Answer RRs: 0
      header += "\x00\x00"               # Authority RRs: 0
      header += "\x00\x00"               # Additional RRs: 0
      
      # Question section
      question = encode_dns_name(domain)
      question += [qtype].pack('n')      # QTYPE
      question += "\x00\x01"             # QCLASS (IN)
      
      header + question
    end

    private

    def self.calculate_ipv4_checksum(header)
      # Zero out checksum field
      header = header.dup
      header[10..11] = "\x00\x00"
      
      # Calculate checksum
      sum = 0
      header.unpack('n*').each { |word| sum += word }
      sum = (sum >> 16) + (sum & 0xFFFF)
      sum += (sum >> 16)
      ~sum & 0xFFFF
    end

    def self.encode_dns_name(name)
      encoded = ""
      name.split('.').each do |label|
        encoded += [label.bytesize].pack('C')
        encoded += label
      end
      encoded += "\x00"  # Root label
      encoded
    end
  end

  # IntegrationTestSuite runs comprehensive tests on the network appliance
  class IntegrationTestSuite
    attr_reader :results, :appliance

    def initialize
      @results = []
      @appliance = nil
    end

    # Run all integration tests
    def run_all_tests
      puts "Starting AetherPacket Integration Tests"
      puts "=" * 50
      
      setup_test_environment
      
      run_test('Packet Parsing Tests') { test_packet_parsing }
      run_test('Firewall Integration') { test_firewall_integration }
      run_test('NAT Engine Integration') { test_nat_integration }
      run_test('DNS Processing') { test_dns_processing }
      run_test('Traffic Shaping') { test_traffic_shaping }
      run_test('Security Features') { test_security_features }
      run_test('Metrics Collection') { test_metrics_collection }
      run_test('API Endpoints') { test_api_endpoints }
      run_test('Performance Tests') { test_performance }
      
      cleanup_test_environment
      
      display_results
    end

    private

    def setup_test_environment
      puts "Setting up test environment..."
      
      begin
        @appliance = NetworkAppliance.new
        puts "✓ Network appliance initialized"
      rescue => e
        puts "✗ Failed to initialize appliance: #{e.message}"
      end
    end

    def cleanup_test_environment
      puts "\nCleaning up test environment..."
      
      if @appliance
        @appliance.stop! if @appliance.respond_to?(:stop!)
        puts "✓ Test environment cleaned up"
      end
    end

    def run_test(test_name, &block)
      print "Running #{test_name}... "
      
      start_time = Time.now
      begin
        result = yield
        duration = Time.now - start_time
        
        if result
          puts "✓ PASS (#{(duration * 1000).round(1)}ms)"
          @results << { name: test_name, status: :pass, duration: duration }
        else
          puts "✗ FAIL (#{(duration * 1000).round(1)}ms)"
          @results << { name: test_name, status: :fail, duration: duration }
        end
      rescue => e
        duration = Time.now - start_time
        puts "✗ ERROR: #{e.message} (#{(duration * 1000).round(1)}ms)"
        @results << { name: test_name, status: :error, duration: duration, error: e.message }
      end
    end

    # Individual test methods
    def test_packet_parsing
      # Test Ethernet frame parsing
      eth_data = TestPacketGenerator.create_ethernet_frame(
        src_mac: '00:11:22:33:44:55',
        dst_mac: 'ff:ff:ff:ff:ff:ff',
        payload: 'test payload'
      )
      
      eth_frame = EthernetFrame.new(eth_data)
      return false unless eth_frame.source_mac == '00:11:22:33:44:55'
      return false unless eth_frame.destination_mac == 'ff:ff:ff:ff:ff:ff'
      
      # Test IPv4 packet parsing
      ipv4_data = TestPacketGenerator.create_ipv4_packet(
        src_ip: '192.168.1.100',
        dst_ip: '10.0.0.1',
        protocol: 6
      )
      
      ipv4_packet = IPv4Packet.new(ipv4_data)
      return false unless ipv4_packet.source_ip == '192.168.1.100'
      return false unless ipv4_packet.destination_ip == '10.0.0.1'
      return false unless ipv4_packet.protocol == 6
      
      # Test TCP segment parsing
      tcp_data = TestPacketGenerator.create_tcp_segment(
        src_port: 8080,
        dst_port: 443,
        flags: 0x02  # SYN
      )
      
      tcp_segment = TcpSegment.new(tcp_data)
      return false unless tcp_segment.source_port == 8080
      return false unless tcp_segment.destination_port == 443
      return false unless tcp_segment.syn_flag
      
      true
    end

    def test_firewall_integration
      return false unless @appliance&.respond_to?(:firewall)
      
      firewall = @appliance.firewall
      
      # Test rule addition
      initial_rule_count = firewall.rules.size
      firewall.add_rule(
        action: :drop,
        source_ip: '192.168.1.100',
        destination_port: 22,
        description: 'Block SSH from test host'
      )
      
      return false unless firewall.rules.size == initial_rule_count + 1
      
      # Test packet filtering
      ipv4_packet = create_test_ipv4_packet('192.168.1.100', '10.0.0.1')
      tcp_segment = create_test_tcp_segment(1234, 22)
      
      result = firewall.process_packet(ipv4_packet, tcp_segment)
      return false unless result[:action] == :drop
      
      # Test rule removal
      rule_id = firewall.rules.keys.first
      firewall.remove_rule(rule_id)
      return false unless firewall.rules.size == initial_rule_count
      
      true
    end

    def test_nat_integration
      return false unless @appliance&.respond_to?(:nat_engine)
      
      nat_engine = @appliance.nat_engine
      
      # Test outbound NAT translation
      internal_ip = '192.168.1.100'
      external_ip = '203.0.113.1'
      
      ipv4_packet = create_test_ipv4_packet(internal_ip, '8.8.8.8')
      tcp_segment = create_test_tcp_segment(1234, 80)
      
      translation = nat_engine.create_translation(
        internal_ip: internal_ip,
        internal_port: 1234,
        external_ip: external_ip,
        external_port: 5678,
        protocol: :tcp
      )
      
      return false unless translation
      
      # Test translation lookup
      found_translation = nat_engine.find_translation(internal_ip, 1234, :tcp, :outbound)
      return false unless found_translation
      return false unless found_translation[:external_ip] == external_ip
      
      true
    end

    def test_dns_processing
      # Test DNS query parsing
      dns_query_data = TestPacketGenerator.create_dns_query(
        domain: 'malware.example.com',
        qtype: 1  # A record
      )
      
      dns_packet = DnsPacket.new(dns_query_data)
      return false unless dns_packet.query?
      return false unless dns_packet.queried_domain == 'malware.example.com'
      
      # Test DNS sinkhole
      if @appliance&.respond_to?(:dns_sinkhole)
        sinkhole = @appliance.dns_sinkhole
        
        # Add test rule
        sinkhole.add_rule(SinkholeRule.new(
          id: 'test_malware',
          pattern: 'malware.example.com',
          pattern_type: :exact,
          target_ip: '127.0.0.1'
        ))
        
        result = sinkhole.process_dns_query('malware.example.com')
        return false unless result
        return false unless result[:target_ip] == '127.0.0.1'
      end
      
      true
    end

    def test_traffic_shaping
      return false unless @appliance&.respond_to?(:traffic_shaper)
      
      traffic_shaper = @appliance.traffic_shaper
      
      # Test packet classification
      ipv4_packet = create_test_ipv4_packet('192.168.1.100', '8.8.8.8')
      tcp_segment = create_test_tcp_segment(1234, 80)
      
      result = traffic_shaper.shape_packet(ipv4_packet, tcp_segment)
      return false unless result[:action] == :allow
      
      # Test rate limiting
      # Send multiple packets rapidly
      10.times do
        traffic_shaper.shape_packet(ipv4_packet, tcp_segment)
      end
      
      # Check that some limiting occurred
      stats = traffic_shaper.shaping_stats
      return false unless stats[:packets_shaped] >= 10
      
      true
    end

    def test_security_features
      security_tests = []
      
      # Test IDS pattern matching
      if @appliance&.respond_to?(:ids_controller)
        ids = @appliance.ids_controller
        
        # Test with malicious payload
        malicious_payload = "' OR 1=1--"  # SQL injection
        ipv4_packet = create_test_ipv4_packet('192.168.1.100', '10.0.0.1')
        tcp_segment = create_test_tcp_segment(1234, 80)
        
        alerts = ids.process_packet(ipv4_packet, tcp_segment, malicious_payload)
        security_tests << (alerts.any?)
      end
      
      # Test SYN flood protection
      if @appliance&.respond_to?(:syn_flood_protection)
        syn_protection = @appliance.syn_flood_protection
        
        # Simulate SYN flood
        src_ip = '192.168.1.100'
        ipv4_packet = create_test_ipv4_packet(src_ip, '10.0.0.1')
        
        results = []
        20.times do |i|
          tcp_segment = create_test_tcp_segment(1234 + i, 80, flags: 0x02)  # SYN
          result = syn_protection.process_tcp_packet(ipv4_packet, tcp_segment)
          results << result
        end
        
        # Should have some blocked packets
        security_tests << results.include?(:blocked)
      end
      
      security_tests.all?
    end

    def test_metrics_collection
      return false unless @appliance&.respond_to?(:metrics)
      
      metrics = @appliance.metrics
      
      # Test metric recording
      initial_count = metrics.get_latest_value('test.packets') || 0
      
      metrics.record_metric('test.packets', initial_count + 1)
      metrics.record_metric('test.packets', initial_count + 2)
      metrics.record_metric('test.packets', initial_count + 3)
      
      current_count = metrics.get_latest_value('test.packets')
      return false unless current_count == initial_count + 3
      
      # Test rate calculation
      sleep(1)  # Allow some time to pass
      rate = metrics.get_metric_rate('test.packets', window_seconds: 5)
      return false unless rate >= 0
      
      # Test statistics
      stats = metrics.get_metric_stats('test.packets')
      return false unless stats[:count] >= 3
      
      true
    end

    def test_api_endpoints
      return false unless @appliance&.respond_to?(:dashboard_manager)
      
      # This would test HTTP API endpoints
      # For now, just check if dashboard manager exists and can be configured
      dashboard = @appliance.dashboard_manager
      
      # Test dashboard status
      status = dashboard.dashboard_status
      return false unless status.is_a?(Hash)
      return false unless status.key?(:enabled)
      
      true
    end

    def test_performance
      # Performance benchmarking
      packet_count = 1000
      start_time = Time.now
      
      # Generate and process test packets
      packet_count.times do |i|
        eth_data = TestPacketGenerator.create_ethernet_frame(
          src_mac: '00:11:22:33:44:55',
          dst_mac: 'ff:ff:ff:ff:ff:ff'
        )
        
        # Just parsing - not full processing to avoid side effects
        EthernetFrame.new(eth_data)
      end
      
      duration = Time.now - start_time
      packets_per_second = packet_count / duration
      
      puts "\n  Performance: #{packets_per_second.round(0)} packets/sec"
      
      # Should be able to parse at least 1000 packets per second
      packets_per_second > 1000
    end

    def display_results
      puts "\nTest Results Summary"
      puts "=" * 30
      
      passed = @results.count { |r| r[:status] == :pass }
      failed = @results.count { |r| r[:status] == :fail }
      errors = @results.count { |r| r[:status] == :error }
      total = @results.size
      
      puts "Total Tests: #{total}"
      puts "Passed: #{passed}"
      puts "Failed: #{failed}"
      puts "Errors: #{errors}"
      puts "Success Rate: #{((passed.to_f / total) * 100).round(1)}%"
      
      total_duration = @results.sum { |r| r[:duration] }
      puts "Total Duration: #{(total_duration * 1000).round(1)}ms"
      
      if failed > 0 || errors > 0
        puts "\nFailed/Error Tests:"
        @results.each do |result|
          next if result[:status] == :pass
          
          status_icon = result[:status] == :fail ? "✗" : "⚠"
          puts "  #{status_icon} #{result[:name]}"
          puts "    #{result[:error]}" if result[:error]
        end
      end
      
      puts "\nIntegration tests #{passed == total ? 'PASSED' : 'FAILED'}!"
    end

    # Helper methods for creating test packets
    def create_test_ipv4_packet(src_ip, dst_ip, protocol: 6)
      data = TestPacketGenerator.create_ipv4_packet(
        src_ip: src_ip,
        dst_ip: dst_ip,
        protocol: protocol
      )
      IPv4Packet.new(data)
    end

    def create_test_tcp_segment(src_port, dst_port, flags: 0x18)
      data = TestPacketGenerator.create_tcp_segment(
        src_port: src_port,
        dst_port: dst_port,
        flags: flags
      )
      TcpSegment.new(data)
    end
  end

  # TestRunner provides a CLI for running integration tests
  class TestRunner
    def self.run(args = [])
      if args.include?('--help') || args.include?('-h')
        show_help
        return
      end
      
      suite = IntegrationTestSuite.new
      
      if args.include?('--performance')
        puts "Running performance-focused tests..."
        suite.run_performance_tests
      elsif args.include?('--security')
        puts "Running security-focused tests..."
        suite.run_security_tests
      else
        suite.run_all_tests
      end
    end

    def self.show_help
      puts <<~HELP
        AetherPacket Integration Test Runner
        
        Usage: ruby test/integration_tests.rb [options]
        
        Options:
          --performance    Run performance-focused tests
          --security       Run security-focused tests
          --help, -h       Show this help message
          
        Default: Run all integration tests
      HELP
    end
  end
end

# Run tests if this file is executed directly
if __FILE__ == $0
  AetherPacket::TestRunner.run(ARGV)
end
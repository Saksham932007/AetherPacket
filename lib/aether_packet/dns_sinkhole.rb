# frozen_string_literal: true

module AetherPacket
  # SinkholeRule defines a DNS sinkhole redirection rule
  class SinkholeRule
    attr_reader :id, :pattern, :pattern_type, :target_ip, :enabled, :metadata

    def initialize(id:, pattern:, target_ip:, pattern_type: :exact, enabled: true, **metadata)
      @id = id
      @pattern = pattern.downcase
      @pattern_type = pattern_type
      @target_ip = target_ip
      @enabled = enabled
      @metadata = metadata
      @compiled_pattern = compile_pattern
    end

    # Check if domain matches this rule
    def matches?(domain)
      return false unless @enabled
      return false unless domain
      
      domain_lower = domain.downcase
      
      case @pattern_type
      when :exact
        domain_lower == @pattern
      when :suffix
        domain_lower.end_with?(@pattern) || domain_lower.end_with?(".#{@pattern}")
      when :prefix
        domain_lower.start_with?(@pattern)
      when :contains
        domain_lower.include?(@pattern)
      when :regex
        !(@compiled_pattern =~ domain_lower).nil?
      when :wildcard
        File.fnmatch(@pattern, domain_lower)
      else
        false
      end
    end

    # Enable/disable rule
    def enabled=(state)
      @enabled = state
    end

    # Get rule information
    def rule_info
      {
        id: @id,
        pattern: @pattern,
        pattern_type: @pattern_type,
        target_ip: @target_ip,
        enabled: @enabled,
        metadata: @metadata
      }
    end

    private

    def compile_pattern
      case @pattern_type
      when :regex
        Regexp.new(@pattern, Regexp::IGNORECASE)
      else
        nil
      end
    end
  end

  # SinkholeEntry tracks sinkholed domains and their access patterns
  class SinkholeEntry
    attr_reader :domain, :first_seen, :last_seen, :access_count, :source_ips, :rule_id

    def initialize(domain, rule_id, source_ip = nil)
      @domain = domain
      @rule_id = rule_id
      @first_seen = Time.now
      @last_seen = Time.now
      @access_count = 1
      @source_ips = Set.new
      @source_ips << source_ip if source_ip
      @mutex = Mutex.new
    end

    # Record new access to this sinkholed domain
    def record_access(source_ip = nil)
      @mutex.synchronize do
        @last_seen = Time.now
        @access_count += 1
        @source_ips << source_ip if source_ip
      end
    end

    # Get entry statistics
    def stats
      @mutex.synchronize do
        {
          domain: @domain,
          rule_id: @rule_id,
          first_seen: @first_seen,
          last_seen: @last_seen,
          access_count: @access_count,
          unique_source_ips: @source_ips.size,
          source_ips: @source_ips.to_a,
          duration_hours: ((@last_seen - @first_seen) / 3600.0).round(2)
        }
      end
    end
  end

  # DnsSinkhole provides malicious domain blocking and redirection
  class DnsSinkhole
    attr_reader :rules, :entries, :default_sinkhole_ip, :enabled, :stats

    def initialize(default_sinkhole_ip: '127.0.0.1', enable_logging: true)
      @rules = {}
      @entries = {}
      @default_sinkhole_ip = default_sinkhole_ip
      @enabled = true
      @enable_logging = enable_logging
      @mutex = Mutex.new
      
      @stats = {
        total_queries: 0,
        sinkholed_queries: 0,
        unique_sinkholed_domains: 0,
        rules_loaded: 0,
        blocked_malware_domains: 0,
        blocked_ad_domains: 0,
        blocked_tracking_domains: 0
      }
      
      load_default_rules
    end

    # Add sinkhole rule
    def add_rule(rule)
      @mutex.synchronize do
        @rules[rule.id] = rule
        @stats[:rules_loaded] += 1
      end
    end

    # Remove rule by ID
    def remove_rule(rule_id)
      @mutex.synchronize do
        rule = @rules.delete(rule_id)
        if rule
          @stats[:rules_loaded] -= 1
          true
        else
          false
        end
      end
    end

    # Process DNS query and check for sinkhole
    def process_dns_query(domain, source_ip = nil)
      @mutex.synchronize { @stats[:total_queries] += 1 }
      
      return nil unless @enabled
      return nil unless domain
      
      # Find matching rule
      matching_rule = find_matching_rule(domain)
      return nil unless matching_rule
      
      # Record sinkhole hit
      @mutex.synchronize do
        @stats[:sinkholed_queries] += 1
        
        # Update category statistics
        update_category_stats(matching_rule)
        
        # Track sinkhole entry
        entry_key = "#{domain}:#{matching_rule.id}"
        if @entries[entry_key]
          @entries[entry_key].record_access(source_ip)
        else
          @entries[entry_key] = SinkholeEntry.new(domain, matching_rule.id, source_ip)
          @stats[:unique_sinkholed_domains] += 1
        end
      end
      
      # Log sinkhole event
      if @enable_logging
        log_sinkhole_event(domain, matching_rule, source_ip)
      end
      
      # Return sinkhole response
      {
        domain: domain,
        rule_id: matching_rule.id,
        target_ip: matching_rule.target_ip,
        rule_pattern: matching_rule.pattern,
        pattern_type: matching_rule.pattern_type,
        metadata: matching_rule.metadata
      }
    end

    # Check if domain should be sinkholed (without recording)
    def should_sinkhole?(domain)
      return false unless @enabled
      !find_matching_rule(domain).nil?
    end

    # Generate DNS response for sinkholed domain
    def generate_sinkhole_response(dns_query_packet, sinkhole_result)
      return nil unless dns_query_packet.query?
      
      # This would generate a proper DNS response packet
      # For now, return the sinkhole IP information
      {
        transaction_id: dns_query_packet.header.transaction_id,
        domain: sinkhole_result[:domain],
        sinkhole_ip: sinkhole_result[:target_ip],
        response_type: :sinkhole
      }
    end

    # Get sinkhole statistics
    def sinkhole_stats
      @mutex.synchronize do
        active_entries = @entries.values.select { |entry| Time.now - entry.last_seen < 3600 }
        
        @stats.merge(
          enabled: @enabled,
          default_sinkhole_ip: @default_sinkhole_ip,
          active_rules: @rules.count { |_, rule| rule.enabled },
          total_rules: @rules.size,
          total_entries: @entries.size,
          active_entries: active_entries.size,
          sinkhole_rate: calculate_sinkhole_rate
        )
      end
    end

    # Get top sinkholed domains
    def top_sinkholed_domains(limit: 20)
      @mutex.synchronize do
        @entries.values
                .map(&:stats)
                .sort_by { |stats| -stats[:access_count] }
                .first(limit)
      end
    end

    # Get recent sinkhole activity
    def recent_activity(hours: 24)
      cutoff_time = Time.now - (hours * 3600)
      
      @mutex.synchronize do
        @entries.values
                .select { |entry| entry.last_seen > cutoff_time }
                .map(&:stats)
                .sort_by { |stats| -stats[:last_seen].to_i }
      end
    end

    # Enable/disable sinkhole
    def enabled=(state)
      @mutex.synchronize { @enabled = state }
    end

    # Load rules from configuration
    def load_rules_from_config(rules_config)
      rules_config.each do |rule_config|
        rule = SinkholeRule.new(**rule_config)
        add_rule(rule)
      end
    end

    # Export sinkhole configuration
    def export_config
      @mutex.synchronize do
        {
          default_sinkhole_ip: @default_sinkhole_ip,
          enabled: @enabled,
          rules: @rules.values.map(&:rule_info)
        }
      end
    end

    # Clear old entries
    def cleanup_old_entries!(max_age_hours: 168)  # 1 week default
      cutoff_time = Time.now - (max_age_hours * 3600)
      
      @mutex.synchronize do
        old_entries = @entries.select { |_, entry| entry.last_seen < cutoff_time }
        old_entries.each { |key, _| @entries.delete(key) }
        
        # Update unique domain count
        @stats[:unique_sinkholed_domains] = @entries.size
        
        old_entries.size
      end
    end

    # Reset statistics
    def reset_stats!
      @mutex.synchronize do
        @stats.each_key { |key| @stats[key] = 0 }
        @entries.clear
      end
    end

    private

    def find_matching_rule(domain)
      @rules.values.find { |rule| rule.matches?(domain) }
    end

    def update_category_stats(rule)
      case rule.metadata[:category]
      when :malware, 'malware'
        @stats[:blocked_malware_domains] += 1
      when :ads, 'ads'
        @stats[:blocked_ad_domains] += 1
      when :tracking, 'tracking'
        @stats[:blocked_tracking_domains] += 1
      end
    end

    def log_sinkhole_event(domain, rule, source_ip)
      category = rule.metadata[:category] || 'unknown'
      puts "SINKHOLE: #{domain} (#{category}) -> #{rule.target_ip} [#{rule.pattern_type}:#{rule.pattern}] from #{source_ip}"
    end

    def calculate_sinkhole_rate
      return 0 if @stats[:total_queries] == 0
      (@stats[:sinkholed_queries].to_f / @stats[:total_queries]) * 100
    end

    def load_default_rules
      default_rules = [
        # Malware domains
        {
          id: 'malware_001',
          pattern: 'evil-malware.com',
          pattern_type: :exact,
          target_ip: '127.0.0.1',
          category: :malware,
          description: 'Known malware C&C domain'
        },
        {
          id: 'malware_002', 
          pattern: '.badware.net',
          pattern_type: :suffix,
          target_ip: '127.0.0.1',
          category: :malware,
          description: 'Malware hosting network'
        },
        # Ad domains
        {
          id: 'ads_001',
          pattern: '.doubleclick.net',
          pattern_type: :suffix,
          target_ip: '127.0.0.1',
          category: :ads,
          description: 'Google ad serving domain'
        },
        {
          id: 'ads_002',
          pattern: 'googleadservices.com',
          pattern_type: :suffix,
          target_ip: '127.0.0.1',
          category: :ads,
          description: 'Google advertising services'
        },
        # Tracking domains
        {
          id: 'tracking_001',
          pattern: '.google-analytics.com',
          pattern_type: :suffix,
          target_ip: '127.0.0.1',
          category: :tracking,
          description: 'Google Analytics tracking'
        },
        {
          id: 'tracking_002',
          pattern: '.facebook.com/tr',
          pattern_type: :contains,
          target_ip: '127.0.0.1',
          category: :tracking,
          description: 'Facebook tracking pixel'
        },
        # Cryptocurrency mining
        {
          id: 'mining_001',
          pattern: 'coinhive.com',
          pattern_type: :suffix,
          target_ip: '127.0.0.1',
          category: :malware,
          description: 'Cryptocurrency mining script'
        },
        # Phishing domains (wildcards)
        {
          id: 'phishing_001',
          pattern: '*paypal-security*',
          pattern_type: :wildcard,
          target_ip: '127.0.0.1',
          category: :malware,
          description: 'Phishing domain pattern'
        }
      ]
      
      default_rules.each do |rule_config|
        rule = SinkholeRule.new(**rule_config)
        add_rule(rule)
      end
    end
  end

  # DnsSinkholeController manages sinkhole integration with DNS processing
  class DnsSinkholeController
    attr_reader :sinkhole, :dns_protocol, :enabled

    def initialize(dns_protocol:, **sinkhole_options)
      @sinkhole = DnsSinkhole.new(**sinkhole_options)
      @dns_protocol = dns_protocol
      @enabled = true
      @mutex = Mutex.new
    end

    # Process DNS packet through sinkhole
    def process_packet_with_sinkhole(udp_payload, source_ip = nil)
      return nil unless @enabled
      
      # Parse DNS packet
      dns_packet = @dns_protocol.process_dns_packet(udp_payload)
      return dns_packet unless dns_packet&.query?
      
      # Check each queried domain for sinkhole
      dns_packet.all_queried_domains.each do |domain|
        sinkhole_result = @sinkhole.process_dns_query(domain, source_ip)
        
        if sinkhole_result
          # Generate sinkhole response
          return generate_sinkhole_dns_response(dns_packet, sinkhole_result)
        end
      end
      
      # No sinkhole hit - return original packet
      dns_packet
    end

    # Check if DNS query should be sinkholed
    def should_sinkhole_query?(domain)
      @enabled && @sinkhole.should_sinkhole?(domain)
    end

    # Enable/disable sinkhole processing
    def enabled=(state)
      @mutex.synchronize { @enabled = state }
      @sinkhole.enabled = state
    end

    # Get comprehensive statistics
    def comprehensive_stats
      dns_stats = @dns_protocol.dns_stats
      sinkhole_stats = @sinkhole.sinkhole_stats
      
      {
        controller_enabled: @enabled,
        dns_stats: dns_stats,
        sinkhole_stats: sinkhole_stats,
        integration_health: calculate_integration_health(dns_stats, sinkhole_stats)
      }
    end

    # Get security insights
    def security_insights
      recent_activity = @sinkhole.recent_activity(hours: 24)
      top_domains = @sinkhole.top_sinkholed_domains(limit: 10)
      
      {
        threat_landscape: analyze_threat_landscape(recent_activity),
        top_blocked_domains: top_domains,
        protection_effectiveness: calculate_protection_effectiveness,
        recommendations: generate_security_recommendations
      }
    end

    # Add custom sinkhole rule
    def add_sinkhole_rule(**rule_params)
      rule = SinkholeRule.new(**rule_params)
      @sinkhole.add_rule(rule)
    end

    private

    def generate_sinkhole_dns_response(dns_packet, sinkhole_result)
      # Create a modified DNS packet indicating sinkhole
      {
        type: :sinkhole_response,
        original_packet: dns_packet,
        sinkhole_result: sinkhole_result,
        transaction_id: dns_packet.header.transaction_id,
        sinkhole_ip: sinkhole_result[:target_ip]
      }
    end

    def calculate_integration_health(dns_stats, sinkhole_stats)
      health_score = 100
      
      # Reduce score for high error rates
      if dns_stats[:parsing_errors] > dns_stats[:packets_processed] * 0.1
        health_score -= 20
      end
      
      # Reduce score if sinkhole is not working
      if sinkhole_stats[:total_queries] > 100 && sinkhole_stats[:sinkhole_rate] == 0
        health_score -= 30
      end
      
      health_score
    end

    def analyze_threat_landscape(recent_activity)
      category_counts = Hash.new(0)
      
      recent_activity.each do |activity|
        # Would need to look up rule category from rule_id
        category_counts[:unknown] += activity[:access_count]
      end
      
      {
        total_threats: recent_activity.size,
        category_breakdown: category_counts,
        trend: recent_activity.size > 50 ? :increasing : :stable
      }
    end

    def calculate_protection_effectiveness
      stats = @sinkhole.sinkhole_stats
      return 0 if stats[:total_queries] == 0
      
      ((stats[:sinkholed_queries].to_f / stats[:total_queries]) * 100).round(2)
    end

    def generate_security_recommendations
      stats = @sinkhole.sinkhole_stats
      recommendations = []
      
      if stats[:sinkhole_rate] < 1
        recommendations << "Consider adding more threat intelligence feeds"
      end
      
      if stats[:total_rules] < 50
        recommendations << "Expand sinkhole rule coverage"
      end
      
      recommendations
    end
  end
end
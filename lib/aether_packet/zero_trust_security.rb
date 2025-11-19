# frozen_string_literal: true

module AetherPacket
  # ZeroTrustPolicyEngine implements comprehensive zero-trust security policies
  class ZeroTrustPolicyEngine
    attr_reader :policies, :enforcement_stats, :trust_cache

    def initialize(default_policy: :deny, cache_ttl: 300)
      @default_policy = default_policy
      @cache_ttl = cache_ttl
      @policies = {}
      @trust_cache = {}
      @enforcement_stats = {
        total_evaluations: 0,
        policy_hits: 0,
        policy_misses: 0,
        allows: 0,
        denies: 0,
        cache_hits: 0,
        cache_misses: 0
      }
      @mutex = Mutex.new
      
      initialize_default_policies
    end

    # Evaluate access request against zero-trust policies
    def evaluate_access(request)
      start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      
      @mutex.synchronize { @enforcement_stats[:total_evaluations] += 1 }
      
      # Check trust cache first
      cache_key = generate_cache_key(request)
      cached_result = check_trust_cache(cache_key)
      
      if cached_result
        @mutex.synchronize { @enforcement_stats[:cache_hits] += 1 }
        return cached_result.merge(cached: true)
      end
      
      @mutex.synchronize { @enforcement_stats[:cache_misses] += 1 }
      
      # Comprehensive zero-trust evaluation
      evaluation_result = {
        request_id: generate_request_id,
        timestamp: Time.now,
        source: request[:source],
        destination: request[:destination],
        action: request[:action],
        context: request[:context] || {},
        policies_evaluated: [],
        trust_score: 0.0,
        risk_factors: [],
        decision: :deny,
        reason: "",
        processing_time_ms: 0
      }
      
      # Step 1: Identity verification
      identity_result = verify_identity(request)
      evaluation_result[:identity] = identity_result
      evaluation_result[:policies_evaluated] << :identity_verification
      
      # Step 2: Device trust assessment
      device_result = assess_device_trust(request)
      evaluation_result[:device] = device_result
      evaluation_result[:policies_evaluated] << :device_trust
      
      # Step 3: Contextual analysis
      context_result = analyze_context(request)
      evaluation_result[:context_analysis] = context_result
      evaluation_result[:policies_evaluated] << :context_analysis
      
      # Step 4: Resource authorization
      resource_result = authorize_resource_access(request)
      evaluation_result[:resource_auth] = resource_result
      evaluation_result[:policies_evaluated] << :resource_authorization
      
      # Step 5: Behavioral analysis
      behavior_result = analyze_behavior(request)
      evaluation_result[:behavior] = behavior_result
      evaluation_result[:policies_evaluated] << :behavioral_analysis
      
      # Step 6: Risk assessment
      risk_result = assess_risk(request, evaluation_result)
      evaluation_result[:risk_assessment] = risk_result
      evaluation_result[:policies_evaluated] << :risk_assessment
      
      # Calculate final trust score and decision
      final_decision = calculate_final_decision(evaluation_result)
      evaluation_result.merge!(final_decision)
      
      # Update enforcement statistics
      update_enforcement_stats(evaluation_result[:decision])
      
      # Cache the result
      cache_trust_decision(cache_key, evaluation_result)
      
      processing_time = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start_time
      evaluation_result[:processing_time_ms] = (processing_time * 1000).round(2)
      
      evaluation_result
    end

    # Add or update security policy
    def add_policy(policy_id, policy_config)
      @mutex.synchronize do
        @policies[policy_id] = {
          id: policy_id,
          config: policy_config,
          created_at: Time.now,
          last_updated: Time.now,
          hit_count: 0
        }
      end
      
      policy_id
    end

    # Remove security policy
    def remove_policy(policy_id)
      @mutex.synchronize { @policies.delete(policy_id) }
    end

    # Update existing policy
    def update_policy(policy_id, policy_config)
      @mutex.synchronize do
        if @policies[policy_id]
          @policies[policy_id][:config] = policy_config
          @policies[policy_id][:last_updated] = Time.now
          true
        else
          false
        end
      end
    end

    # Get policy enforcement statistics
    def enforcement_statistics
      @mutex.synchronize do
        {
          enforcement_stats: @enforcement_stats.dup,
          policy_count: @policies.size,
          cache_size: @trust_cache.size,
          cache_hit_ratio: calculate_cache_hit_ratio,
          allow_deny_ratio: calculate_allow_deny_ratio,
          top_policies: get_top_policies
        }
      end
    end

    # Clear trust cache
    def clear_cache
      @mutex.synchronize { @trust_cache.clear }
    end

    # Reset all statistics
    def reset_statistics
      @mutex.synchronize do
        @enforcement_stats.each_key { |key| @enforcement_stats[key] = 0 }
        @policies.each_value { |policy| policy[:hit_count] = 0 }
      end
    end

    private

    def initialize_default_policies
      # Default identity verification policy
      add_policy(:identity_verification, {
        type: :identity,
        requires_authentication: true,
        allowed_identity_sources: [:ldap, :saml, :oauth2, :certificate],
        mfa_required: true,
        session_timeout: 3600
      })
      
      # Default device trust policy
      add_policy(:device_trust, {
        type: :device,
        requires_device_certificate: true,
        allowed_device_types: [:workstation, :mobile, :server],
        requires_compliance_check: true,
        quarantine_unknown_devices: true
      })
      
      # Default network segmentation policy
      add_policy(:network_segmentation, {
        type: :network,
        micro_segmentation_enabled: true,
        default_network_policy: :deny,
        allowed_network_zones: [:internal, :dmz],
        cross_zone_inspection: true
      })
      
      # Default data protection policy
      add_policy(:data_protection, {
        type: :data,
        encryption_required: true,
        dlp_enabled: true,
        data_classification_required: true,
        allowed_data_flows: [:read, :write_restricted]
      })
    end

    def generate_cache_key(request)
      key_components = [
        request[:source][:identity],
        request[:source][:device_id],
        request[:destination][:resource],
        request[:action],
        request[:context]&.dig(:location),
        request[:context]&.dig(:time_of_day)
      ].compact
      
      Digest::SHA256.hexdigest(key_components.join(":"))
    end

    def generate_request_id
      "zt_#{SecureRandom.hex(8)}"
    end

    def check_trust_cache(cache_key)
      @mutex.synchronize do
        cache_entry = @trust_cache[cache_key]
        
        if cache_entry && (Time.now - cache_entry[:cached_at]) < @cache_ttl
          cache_entry[:result]
        else
          @trust_cache.delete(cache_key) if cache_entry
          nil
        end
      end
    end

    def cache_trust_decision(cache_key, result)
      # Only cache successful evaluations to avoid caching errors
      return unless [:allow, :deny].include?(result[:decision])
      
      @mutex.synchronize do
        @trust_cache[cache_key] = {
          result: result.dup,
          cached_at: Time.now
        }
        
        # Cleanup old cache entries
        cleanup_expired_cache_entries
      end
    end

    def cleanup_expired_cache_entries
      current_time = Time.now
      
      @trust_cache.delete_if do |_, entry|
        current_time - entry[:cached_at] > @cache_ttl
      end
    end

    def verify_identity(request)
      identity = request[:source][:identity]
      
      result = {
        verified: false,
        trust_score: 0.0,
        factors: [],
        warnings: []
      }
      
      # Check if identity is provided
      unless identity
        result[:warnings] << "No identity provided"
        return result
      end
      
      # Verify identity source
      identity_source = request[:source][:identity_source]
      policy = @policies[:identity_verification][:config]
      
      if policy[:allowed_identity_sources].include?(identity_source)
        result[:trust_score] += 0.3
        result[:factors] << "Valid identity source: #{identity_source}"
      else
        result[:warnings] << "Untrusted identity source: #{identity_source}"
        return result
      end
      
      # Check authentication strength
      auth_method = request[:source][:auth_method]
      if auth_method == :mfa && policy[:mfa_required]
        result[:trust_score] += 0.4
        result[:factors] << "Multi-factor authentication verified"
      elsif auth_method == :password
        result[:trust_score] += 0.2
        result[:warnings] << "Single-factor authentication (MFA recommended)"
      end
      
      # Check session freshness
      session_age = request[:context][:session_age] || 0
      if session_age < policy[:session_timeout]
        result[:trust_score] += 0.3
        result[:factors] << "Fresh authentication session"
      else
        result[:warnings] << "Stale authentication session"
      end
      
      result[:verified] = result[:trust_score] >= 0.5
      result
    end

    def assess_device_trust(request)
      device = request[:source][:device]
      
      result = {
        trusted: false,
        trust_score: 0.0,
        factors: [],
        warnings: []
      }
      
      return result unless device
      
      policy = @policies[:device_trust][:config]
      
      # Check device certificate
      if device[:has_certificate] && policy[:requires_device_certificate]
        result[:trust_score] += 0.3
        result[:factors] << "Valid device certificate"
      else
        result[:warnings] << "Missing or invalid device certificate"
      end
      
      # Check device type
      device_type = device[:type]
      if policy[:allowed_device_types].include?(device_type)
        result[:trust_score] += 0.2
        result[:factors] << "Allowed device type: #{device_type}"
      else
        result[:warnings] << "Restricted device type: #{device_type}"
      end
      
      # Check compliance status
      if device[:compliant] && policy[:requires_compliance_check]
        result[:trust_score] += 0.3
        result[:factors] << "Device compliance verified"
      else
        result[:warnings] << "Device compliance check failed"
      end
      
      # Check device reputation
      device_reputation = device[:reputation_score] || 0
      if device_reputation > 0.8
        result[:trust_score] += 0.2
        result[:factors] << "High device reputation score"
      elsif device_reputation < 0.3
        result[:warnings] << "Low device reputation score"
      end
      
      result[:trusted] = result[:trust_score] >= 0.5
      result
    end

    def analyze_context(request)
      context = request[:context] || {}
      
      result = {
        contextual_trust: 0.0,
        factors: [],
        warnings: []
      }
      
      # Location analysis
      if context[:location]
        location_trust = analyze_location_context(context[:location])
        result[:contextual_trust] += location_trust[:score]
        result[:factors].concat(location_trust[:factors])
        result[:warnings].concat(location_trust[:warnings])
      end
      
      # Time-based analysis
      if context[:timestamp]
        time_trust = analyze_time_context(context[:timestamp])
        result[:contextual_trust] += time_trust[:score]
        result[:factors].concat(time_trust[:factors])
        result[:warnings].concat(time_trust[:warnings])
      end
      
      # Network context analysis
      if context[:network]
        network_trust = analyze_network_context(context[:network])
        result[:contextual_trust] += network_trust[:score]
        result[:factors].concat(network_trust[:factors])
        result[:warnings].concat(network_trust[:warnings])
      end
      
      # Normalize contextual trust score
      result[:contextual_trust] = [result[:contextual_trust], 1.0].min
      
      result
    end

    def authorize_resource_access(request)
      resource = request[:destination][:resource]
      action = request[:action]
      identity = request[:source][:identity]
      
      result = {
        authorized: false,
        authorization_score: 0.0,
        permissions: [],
        restrictions: []
      }
      
      # Check resource permissions
      permissions = get_resource_permissions(identity, resource)
      
      if permissions[:allowed_actions].include?(action)
        result[:authorization_score] += 0.5
        result[:permissions] << "Action '#{action}' permitted for resource '#{resource}'"
      else
        result[:restrictions] << "Action '#{action}' denied for resource '#{resource}'"
        return result
      end
      
      # Check data classification requirements
      resource_classification = get_resource_classification(resource)
      identity_clearance = get_identity_clearance(identity)
      
      if identity_clearance >= resource_classification
        result[:authorization_score] += 0.3
        result[:permissions] << "Sufficient clearance for resource classification"
      else
        result[:restrictions] << "Insufficient clearance for resource access"
        return result
      end
      
      # Check time-based restrictions
      time_restrictions = permissions[:time_restrictions]
      if time_restrictions && !within_allowed_time(Time.now, time_restrictions)
        result[:restrictions] << "Access outside allowed time window"
        return result
      else
        result[:authorization_score] += 0.2
        result[:permissions] << "Within allowed access time window"
      end
      
      result[:authorized] = result[:authorization_score] >= 0.7
      result
    end

    def analyze_behavior(request)
      identity = request[:source][:identity]
      
      result = {
        behavioral_trust: 0.0,
        anomaly_score: 0.0,
        patterns: [],
        anomalies: []
      }
      
      # Get historical behavior patterns
      behavior_history = get_behavior_history(identity)
      
      # Analyze access patterns
      access_pattern = analyze_access_pattern(request, behavior_history)
      result[:behavioral_trust] += access_pattern[:trust_score]
      result[:patterns].concat(access_pattern[:patterns])
      result[:anomalies].concat(access_pattern[:anomalies])
      
      # Analyze temporal patterns
      temporal_pattern = analyze_temporal_pattern(request, behavior_history)
      result[:behavioral_trust] += temporal_pattern[:trust_score]
      result[:patterns].concat(temporal_pattern[:patterns])
      result[:anomalies].concat(temporal_pattern[:anomalies])
      
      # Analyze resource usage patterns
      usage_pattern = analyze_usage_pattern(request, behavior_history)
      result[:behavioral_trust] += usage_pattern[:trust_score]
      result[:patterns].concat(usage_pattern[:patterns])
      result[:anomalies].concat(usage_pattern[:anomalies])
      
      # Calculate overall anomaly score
      result[:anomaly_score] = result[:anomalies].size * 0.2
      result[:behavioral_trust] = [result[:behavioral_trust] - result[:anomaly_score], 0.0].max
      result[:behavioral_trust] = [result[:behavioral_trust], 1.0].min
      
      result
    end

    def assess_risk(request, evaluation_context)
      risk_factors = []
      risk_score = 0.0
      
      # Identity risk factors
      if evaluation_context[:identity][:warnings].any?
        risk_score += 0.2
        risk_factors << "Identity verification concerns"
      end
      
      # Device risk factors
      if evaluation_context[:device][:warnings].any?
        risk_score += 0.2
        risk_factors << "Device trust concerns"
      end
      
      # Behavioral risk factors
      if evaluation_context[:behavior][:anomaly_score] > 0.3
        risk_score += 0.3
        risk_factors << "Behavioral anomalies detected"
      end
      
      # Context risk factors
      if evaluation_context[:context_analysis][:warnings].any?
        risk_score += 0.15
        risk_factors << "Contextual risk factors present"
      end
      
      # Resource sensitivity
      resource_sensitivity = get_resource_sensitivity(request[:destination][:resource])
      if resource_sensitivity == :high
        risk_score += 0.1
        risk_factors << "High-sensitivity resource access"
      end
      
      # Action risk level
      action_risk = get_action_risk_level(request[:action])
      risk_score += action_risk * 0.05
      
      risk_level = case risk_score
                  when 0.0..0.2 then :low
                  when 0.2..0.5 then :medium
                  when 0.5..0.8 then :high
                  else :critical
                  end
      
      {
        risk_score: [risk_score, 1.0].min,
        risk_level: risk_level,
        risk_factors: risk_factors,
        mitigation_required: risk_score > 0.5
      }
    end

    def calculate_final_decision(evaluation_result)
      # Aggregate trust scores from all components
      trust_components = [
        evaluation_result[:identity][:trust_score] * 0.25,
        evaluation_result[:device][:trust_score] * 0.20,
        evaluation_result[:context_analysis][:contextual_trust] * 0.15,
        evaluation_result[:resource_auth][:authorization_score] * 0.25,
        evaluation_result[:behavior][:behavioral_trust] * 0.15
      ]
      
      overall_trust_score = trust_components.sum
      risk_score = evaluation_result[:risk_assessment][:risk_score]
      
      # Apply risk penalty
      adjusted_trust_score = overall_trust_score - (risk_score * 0.5)
      adjusted_trust_score = [adjusted_trust_score, 0.0].max
      
      # Determine final decision
      decision = if adjusted_trust_score >= 0.8
                  :allow
                elsif adjusted_trust_score >= 0.6 && risk_score < 0.3
                  :allow_with_monitoring
                elsif adjusted_trust_score >= 0.4
                  :conditional_allow
                else
                  :deny
                end
      
      # Generate decision reason
      reason = generate_decision_reason(evaluation_result, decision, adjusted_trust_score)
      
      {
        decision: decision,
        trust_score: adjusted_trust_score.round(3),
        risk_score: risk_score.round(3),
        reason: reason,
        recommendations: generate_recommendations(evaluation_result, decision)
      }
    end

    def update_enforcement_stats(decision)
      @mutex.synchronize do
        case decision
        when :allow, :allow_with_monitoring, :conditional_allow
          @enforcement_stats[:allows] += 1
        when :deny
          @enforcement_stats[:denies] += 1
        end
      end
    end

    # Helper methods for context analysis
    def analyze_location_context(location)
      # Simplified location analysis
      trusted_locations = ["office", "home", "datacenter"]
      
      if trusted_locations.include?(location[:type])
        { score: 0.3, factors: ["Trusted location: #{location[:type]}"], warnings: [] }
      else
        { score: 0.0, factors: [], warnings: ["Untrusted location: #{location[:type]}"] }
      end
    end

    def analyze_time_context(timestamp)
      hour = Time.at(timestamp).hour
      
      if hour >= 9 && hour <= 17  # Business hours
        { score: 0.2, factors: ["Access during business hours"], warnings: [] }
      else
        { score: 0.0, factors: [], warnings: ["Access outside business hours"] }
      end
    end

    def analyze_network_context(network)
      trusted_networks = ["corporate", "vpn", "secure"]
      
      if trusted_networks.include?(network[:type])
        { score: 0.3, factors: ["Trusted network: #{network[:type]}"], warnings: [] }
      else
        { score: 0.0, factors: [], warnings: ["Untrusted network: #{network[:type]}"] }
      end
    end

    # Helper methods for resource authorization
    def get_resource_permissions(identity, resource)
      # Simplified permission lookup
      {
        allowed_actions: [:read, :write, :execute],
        time_restrictions: { start_hour: 9, end_hour: 17 }
      }
    end

    def get_resource_classification(resource)
      # Simplified classification: 1=public, 2=internal, 3=confidential, 4=secret
      resource.to_s.include?("secret") ? 4 : 2
    end

    def get_identity_clearance(identity)
      # Simplified clearance lookup
      3  # Most users have level 3 clearance
    end

    def within_allowed_time(current_time, restrictions)
      hour = current_time.hour
      hour >= restrictions[:start_hour] && hour <= restrictions[:end_hour]
    end

    # Helper methods for behavioral analysis
    def get_behavior_history(identity)
      # Simplified behavior history
      {
        typical_access_hours: (9..17).to_a,
        common_resources: ["email", "documents", "applications"],
        average_session_duration: 240  # minutes
      }
    end

    def analyze_access_pattern(request, history)
      patterns = []
      anomalies = []
      trust_score = 0.3
      
      resource = request[:destination][:resource]
      if history[:common_resources].include?(resource)
        patterns << "Typical resource access"
        trust_score += 0.2
      else
        anomalies << "Unusual resource access"
      end
      
      { trust_score: trust_score, patterns: patterns, anomalies: anomalies }
    end

    def analyze_temporal_pattern(request, history)
      patterns = []
      anomalies = []
      trust_score = 0.2
      
      hour = Time.now.hour
      if history[:typical_access_hours].include?(hour)
        patterns << "Typical access time"
        trust_score += 0.2
      else
        anomalies << "Unusual access time"
      end
      
      { trust_score: trust_score, patterns: patterns, anomalies: anomalies }
    end

    def analyze_usage_pattern(request, history)
      patterns = []
      anomalies = []
      trust_score = 0.1
      
      # Simplified usage pattern analysis
      patterns << "Normal usage pattern"
      
      { trust_score: trust_score, patterns: patterns, anomalies: anomalies }
    end

    # Helper methods for risk assessment
    def get_resource_sensitivity(resource)
      resource.to_s.include?("confidential") ? :high : :medium
    end

    def get_action_risk_level(action)
      case action
      when :read then 1
      when :write then 3
      when :execute then 5
      when :delete then 8
      else 2
      end
    end

    # Helper methods for decision generation
    def generate_decision_reason(evaluation_result, decision, trust_score)
      case decision
      when :allow
        "High trust score (#{trust_score.round(2)}) with all security checks passed"
      when :allow_with_monitoring
        "Moderate trust score (#{trust_score.round(2)}) requires enhanced monitoring"
      when :conditional_allow
        "Low trust score (#{trust_score.round(2)}) requires additional verification"
      when :deny
        "Insufficient trust score (#{trust_score.round(2)}) or high risk factors present"
      end
    end

    def generate_recommendations(evaluation_result, decision)
      recommendations = []
      
      case decision
      when :deny
        recommendations << "Improve identity verification (MFA, fresh authentication)"
        recommendations << "Use trusted device with valid certificate"
        recommendations << "Access from approved network location"
      when :conditional_allow
        recommendations << "Enable enhanced monitoring for this session"
        recommendations << "Require step-up authentication for sensitive operations"
      when :allow_with_monitoring
        recommendations << "Monitor for behavioral anomalies"
        recommendations << "Log all actions for security review"
      end
      
      recommendations
    end

    # Statistics helper methods
    def calculate_cache_hit_ratio
      total = @enforcement_stats[:cache_hits] + @enforcement_stats[:cache_misses]
      return 0.0 if total == 0
      (@enforcement_stats[:cache_hits].to_f / total).round(3)
    end

    def calculate_allow_deny_ratio
      total = @enforcement_stats[:allows] + @enforcement_stats[:denies]
      return 0.0 if total == 0
      (@enforcement_stats[:allows].to_f / total).round(3)
    end

    def get_top_policies
      @policies.values
               .sort_by { |policy| -policy[:hit_count] }
               .first(5)
               .map { |policy| { id: policy[:id], hits: policy[:hit_count] } }
    end
  end

  # MicroSegmentationEngine provides network-level zero-trust enforcement
  class MicroSegmentationEngine
    attr_reader :segments, :policies, :enforcement_stats

    def initialize
      @segments = {}
      @policies = {}
      @enforcement_stats = {
        total_flows: 0,
        allowed_flows: 0,
        denied_flows: 0,
        policy_violations: 0
      }
      @mutex = Mutex.new
      
      initialize_default_segments
    end

    # Create network micro-segment
    def create_segment(segment_id, config)
      @mutex.synchronize do
        @segments[segment_id] = {
          id: segment_id,
          name: config[:name],
          network_range: config[:network_range],
          security_level: config[:security_level] || :medium,
          allowed_protocols: config[:allowed_protocols] || [],
          isolation_level: config[:isolation_level] || :strict,
          created_at: Time.now
        }
      end
      
      segment_id
    end

    # Create inter-segment policy
    def create_policy(policy_id, from_segment, to_segment, rules)
      @mutex.synchronize do
        @policies[policy_id] = {
          id: policy_id,
          from_segment: from_segment,
          to_segment: to_segment,
          rules: rules,
          created_at: Time.now,
          hit_count: 0
        }
      end
      
      policy_id
    end

    # Evaluate network flow against micro-segmentation policies
    def evaluate_flow(flow)
      @mutex.synchronize { @enforcement_stats[:total_flows] += 1 }
      
      source_segment = identify_segment(flow[:source_ip])
      dest_segment = identify_segment(flow[:dest_ip])
      
      result = {
        flow_id: generate_flow_id(flow),
        source_segment: source_segment,
        destination_segment: dest_segment,
        decision: :deny,
        applied_policies: [],
        violations: []
      }
      
      # Check if both endpoints are in managed segments
      unless source_segment && dest_segment
        result[:violations] << "Unmanaged network endpoint"
        update_enforcement_stats(:deny)
        return result
      end
      
      # Find applicable policies
      applicable_policies = find_applicable_policies(source_segment, dest_segment)
      
      if applicable_policies.empty?
        # Default deny for zero-trust
        result[:violations] << "No explicit policy allows this flow"
        update_enforcement_stats(:deny)
        return result
      end
      
      # Evaluate each policy
      policy_results = applicable_policies.map do |policy|
        evaluate_policy(policy, flow)
      end
      
      result[:applied_policies] = policy_results
      
      # Determine final decision (any allow wins, but collect violations)
      if policy_results.any? { |pr| pr[:decision] == :allow }
        result[:decision] = :allow
        update_enforcement_stats(:allow)
      else
        result[:decision] = :deny
        result[:violations].concat(policy_results.flat_map { |pr| pr[:violations] })
        update_enforcement_stats(:deny)
      end
      
      result
    end

    # Get micro-segmentation statistics
    def segmentation_stats
      @mutex.synchronize do
        {
          total_segments: @segments.size,
          total_policies: @policies.size,
          enforcement_stats: @enforcement_stats.dup,
          segments: @segments.transform_values { |seg| seg.slice(:name, :security_level, :isolation_level) },
          top_policies: get_top_policies
        }
      end
    end

    private

    def initialize_default_segments
      # Default network segments
      create_segment(:dmz, {
        name: "DMZ Zone",
        network_range: "10.0.1.0/24",
        security_level: :low,
        allowed_protocols: [:http, :https, :ssh],
        isolation_level: :moderate
      })
      
      create_segment(:internal, {
        name: "Internal Network",
        network_range: "10.0.2.0/24",
        security_level: :medium,
        allowed_protocols: [:http, :https, :ssh, :rdp, :smb],
        isolation_level: :moderate
      })
      
      create_segment(:secure, {
        name: "Secure Zone",
        network_range: "10.0.3.0/24",
        security_level: :high,
        allowed_protocols: [:https, :ssh],
        isolation_level: :strict
      })
      
      # Default policies
      create_policy(:dmz_to_internal, :dmz, :internal, {
        allow: false,
        protocols: [],
        ports: [],
        conditions: []
      })
      
      create_policy(:internal_to_secure, :internal, :secure, {
        allow: true,
        protocols: [:https],
        ports: [443],
        conditions: [:authenticated, :encrypted]
      })
    end

    def identify_segment(ip_address)
      # Simplified segment identification based on IP range
      @segments.each do |segment_id, segment|
        if ip_in_range?(ip_address, segment[:network_range])
          return segment_id
        end
      end
      
      nil
    end

    def ip_in_range?(ip, range)
      # Simplified IP range check
      network, prefix = range.split("/")
      prefix = prefix.to_i
      
      # Basic IP range matching (simplified)
      network_parts = network.split(".").map(&:to_i)
      ip_parts = ip.split(".").map(&:to_i)
      
      # Check first octets based on prefix (simplified)
      octets_to_check = (prefix / 8).to_i
      octets_to_check.times do |i|
        return false if network_parts[i] != ip_parts[i]
      end
      
      true
    end

    def find_applicable_policies(source_segment, dest_segment)
      @policies.values.select do |policy|
        policy[:from_segment] == source_segment && 
        policy[:to_segment] == dest_segment
      end
    end

    def evaluate_policy(policy, flow)
      rules = policy[:rules]
      violations = []
      
      # Update policy hit count
      @mutex.synchronize { policy[:hit_count] += 1 }
      
      # Check if policy allows the flow
      unless rules[:allow]
        violations << "Policy explicitly denies flow"
        return { policy_id: policy[:id], decision: :deny, violations: violations }
      end
      
      # Check protocol
      if rules[:protocols].any? && !rules[:protocols].include?(flow[:protocol])
        violations << "Protocol #{flow[:protocol]} not allowed"
      end
      
      # Check port
      if rules[:ports].any? && !rules[:ports].include?(flow[:dest_port])
        violations << "Port #{flow[:dest_port]} not allowed"
      end
      
      # Check conditions
      if rules[:conditions]
        rules[:conditions].each do |condition|
          unless check_flow_condition(flow, condition)
            violations << "Condition #{condition} not met"
          end
        end
      end
      
      decision = violations.empty? ? :allow : :deny
      
      { policy_id: policy[:id], decision: decision, violations: violations }
    end

    def check_flow_condition(flow, condition)
      case condition
      when :authenticated
        flow[:authenticated] == true
      when :encrypted
        flow[:encrypted] == true
      when :logged
        flow[:logged] == true
      else
        false
      end
    end

    def generate_flow_id(flow)
      "flow_#{SecureRandom.hex(6)}"
    end

    def update_enforcement_stats(decision)
      @mutex.synchronize do
        case decision
        when :allow
          @enforcement_stats[:allowed_flows] += 1
        when :deny
          @enforcement_stats[:denied_flows] += 1
          @enforcement_stats[:policy_violations] += 1
        end
      end
    end

    def get_top_policies
      @policies.values
               .sort_by { |policy| -policy[:hit_count] }
               .first(5)
               .map { |policy| { id: policy[:id], hits: policy[:hit_count] } }
    end
  end
end
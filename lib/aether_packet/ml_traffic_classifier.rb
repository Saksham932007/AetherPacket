# frozen_string_literal: true

module AetherPacket
  # NetworkFeatureExtractor extracts ML features from network traffic
  class NetworkFeatureExtractor
    attr_reader :flow_cache, :feature_stats

    def initialize(flow_timeout: 300)
      @flow_timeout = flow_timeout
      @flow_cache = {}
      @feature_stats = {
        flows_analyzed: 0,
        features_extracted: 0,
        cache_hits: 0,
        cache_misses: 0
      }
      @mutex = Mutex.new
    end

    # Extract comprehensive flow features from packet sequence
    def extract_flow_features(packet_sequence)
      return {} if packet_sequence.empty?

      @mutex.synchronize do
        @feature_stats[:flows_analyzed] += 1
        @feature_stats[:features_extracted] += 1
      end

      # Basic flow identification
      flow_id = generate_flow_id(packet_sequence.first)
      
      # Update flow cache
      flow_info = update_flow_cache(flow_id, packet_sequence)
      
      {
        flow_id: flow_id,
        protocol_features: extract_protocol_features(packet_sequence),
        behavioral_features: extract_behavioral_features(flow_info),
        payload_features: extract_payload_features(packet_sequence),
        temporal_features: extract_temporal_features(packet_sequence),
        statistical_features: extract_statistical_features(packet_sequence)
      }
    end

    # Extract protocol-level features
    def extract_protocol_features(packet_sequence)
      features = {}
      
      # Protocol distribution
      protocol_counts = Hash.new(0)
      packet_sequence.each do |packet|
        protocol = extract_protocol(packet)
        protocol_counts[protocol] += 1
      end
      
      features[:protocol_distribution] = protocol_counts
      features[:dominant_protocol] = protocol_counts.max_by { |_, count| count }&.first
      features[:protocol_diversity] = protocol_counts.keys.size
      
      # TCP specific features
      tcp_packets = packet_sequence.select { |p| extract_protocol(p) == :tcp }
      if tcp_packets.any?
        features[:tcp_flags] = extract_tcp_flags_distribution(tcp_packets)
        features[:tcp_window_sizes] = tcp_packets.map { |p| extract_tcp_window(p) }.compact
        features[:tcp_options] = extract_tcp_options_frequency(tcp_packets)
      end
      
      # UDP specific features
      udp_packets = packet_sequence.select { |p| extract_protocol(p) == :udp }
      if udp_packets.any?
        features[:udp_port_distribution] = extract_port_distribution(udp_packets)
      end
      
      # ICMP features
      icmp_packets = packet_sequence.select { |p| extract_protocol(p) == :icmp }
      if icmp_packets.any?
        features[:icmp_types] = extract_icmp_types(icmp_packets)
      end
      
      features
    end

    # Extract behavioral features for anomaly detection
    def extract_behavioral_features(flow_info)
      features = {}
      
      # Flow duration and packet timing
      features[:flow_duration] = flow_info[:duration]
      features[:packet_count] = flow_info[:packet_count]
      features[:bytes_total] = flow_info[:bytes_total]
      features[:packets_per_second] = flow_info[:packet_count] / [flow_info[:duration], 1].max
      features[:bytes_per_second] = flow_info[:bytes_total] / [flow_info[:duration], 1].max
      
      # Inter-arrival time statistics
      if flow_info[:inter_arrival_times].any?
        iat = flow_info[:inter_arrival_times]
        features[:iat_mean] = iat.sum / iat.size
        features[:iat_std] = calculate_standard_deviation(iat)
        features[:iat_min] = iat.min
        features[:iat_max] = iat.max
        features[:iat_median] = iat.sort[iat.size / 2]
      end
      
      # Packet size statistics
      if flow_info[:packet_sizes].any?
        sizes = flow_info[:packet_sizes]
        features[:size_mean] = sizes.sum / sizes.size
        features[:size_std] = calculate_standard_deviation(sizes)
        features[:size_min] = sizes.min
        features[:size_max] = sizes.max
        features[:size_variance] = calculate_variance(sizes)
      end
      
      # Flow directionality (if source/dest info available)
      features[:bidirectional_packets] = flow_info[:bidirectional_packets] || 0
      features[:forward_packets] = flow_info[:forward_packets] || 0
      features[:backward_packets] = flow_info[:backward_packets] || 0
      
      # Burst analysis
      features[:burst_count] = flow_info[:burst_count] || 0
      features[:avg_burst_size] = flow_info[:avg_burst_size] || 0
      
      features
    end

    # Extract payload-based features for DPI and malware detection
    def extract_payload_features(packet_sequence)
      features = {}
      
      # Payload length statistics
      payload_lengths = packet_sequence.map { |p| extract_payload_length(p) }.compact
      if payload_lengths.any?
        features[:payload_length_mean] = payload_lengths.sum / payload_lengths.size
        features[:payload_length_std] = calculate_standard_deviation(payload_lengths)
        features[:zero_payload_ratio] = payload_lengths.count(0) / payload_lengths.size.to_f
      end
      
      # Entropy analysis for encrypted/compressed content
      payloads = packet_sequence.map { |p| extract_payload(p) }.compact.reject(&:empty?)
      if payloads.any?
        entropies = payloads.map { |payload| calculate_entropy(payload) }
        features[:payload_entropy_mean] = entropies.sum / entropies.size
        features[:payload_entropy_std] = calculate_standard_deviation(entropies)
        features[:high_entropy_ratio] = entropies.count { |e| e > 7.5 } / entropies.size.to_f
      end
      
      # Byte frequency analysis
      if payloads.any?
        byte_frequencies = analyze_byte_frequencies(payloads.join)
        features[:byte_frequency_entropy] = calculate_entropy_from_frequencies(byte_frequencies)
        features[:ascii_ratio] = calculate_ascii_ratio(payloads.join)
        features[:printable_ratio] = calculate_printable_ratio(payloads.join)
      end
      
      # Pattern matching for known protocols
      features[:http_indicators] = detect_http_patterns(payloads)
      features[:dns_indicators] = detect_dns_patterns(payloads)
      features[:tls_indicators] = detect_tls_patterns(payloads)
      
      features
    end

    # Extract temporal features
    def extract_temporal_features(packet_sequence)
      features = {}
      
      return features if packet_sequence.size < 2
      
      timestamps = packet_sequence.map { |p| extract_timestamp(p) }.compact.sort
      
      # Flow temporal characteristics
      features[:flow_start_time] = timestamps.first
      features[:flow_end_time] = timestamps.last
      features[:flow_duration] = timestamps.last - timestamps.first
      
      # Time-based patterns
      features[:time_of_day] = extract_time_of_day_features(timestamps)
      features[:day_of_week] = extract_day_of_week_features(timestamps)
      
      # Activity patterns
      features[:active_periods] = identify_active_periods(timestamps)
      features[:idle_periods] = identify_idle_periods(timestamps)
      
      features
    end

    # Extract statistical features for ML models
    def extract_statistical_features(packet_sequence)
      features = {}
      
      # Basic statistics
      features[:packet_count] = packet_sequence.size
      features[:total_bytes] = packet_sequence.sum { |p| extract_packet_size(p) }
      
      # Rate-based features
      if packet_sequence.size > 1
        duration = extract_timestamp(packet_sequence.last) - extract_timestamp(packet_sequence.first)
        features[:packet_rate] = packet_sequence.size / [duration, 1].max
        features[:byte_rate] = features[:total_bytes] / [duration, 1].max
      end
      
      # Variability measures
      packet_sizes = packet_sequence.map { |p| extract_packet_size(p) }
      features[:coefficient_of_variation] = calculate_coefficient_of_variation(packet_sizes)
      
      # Periodicity detection
      features[:periodic_score] = detect_periodicity(packet_sequence)
      
      # Randomness measures
      features[:randomness_score] = calculate_randomness_score(packet_sequence)
      
      features
    end

    # Get feature extraction statistics
    def extraction_stats
      @mutex.synchronize { @feature_stats.dup }
    end

    # Clear flow cache and reset statistics
    def reset!
      @mutex.synchronize do
        @flow_cache.clear
        @feature_stats.each_key { |key| @feature_stats[key] = 0 }
      end
    end

    private

    def generate_flow_id(packet)
      # Generate 5-tuple flow identifier
      src_ip = extract_source_ip(packet)
      dst_ip = extract_destination_ip(packet)
      src_port = extract_source_port(packet)
      dst_port = extract_destination_port(packet)
      protocol = extract_protocol(packet)
      
      "#{src_ip}:#{src_port}-#{dst_ip}:#{dst_port}-#{protocol}"
    end

    def update_flow_cache(flow_id, packet_sequence)
      current_time = Time.now
      
      if @flow_cache[flow_id]
        @feature_stats[:cache_hits] += 1
        flow_info = @flow_cache[flow_id]
      else
        @feature_stats[:cache_misses] += 1
        flow_info = {
          first_seen: current_time,
          packet_count: 0,
          bytes_total: 0,
          packet_sizes: [],
          inter_arrival_times: [],
          last_packet_time: nil
        }
        @flow_cache[flow_id] = flow_info
      end
      
      # Update flow information with new packets
      packet_sequence.each do |packet|
        packet_time = extract_timestamp(packet)
        packet_size = extract_packet_size(packet)
        
        if flow_info[:last_packet_time]
          iat = packet_time - flow_info[:last_packet_time]
          flow_info[:inter_arrival_times] << iat
        end
        
        flow_info[:packet_count] += 1
        flow_info[:bytes_total] += packet_size
        flow_info[:packet_sizes] << packet_size
        flow_info[:last_packet_time] = packet_time
      end
      
      flow_info[:duration] = current_time - flow_info[:first_seen]
      
      # Cleanup old flows
      cleanup_expired_flows
      
      flow_info
    end

    def cleanup_expired_flows
      current_time = Time.now
      
      @flow_cache.delete_if do |_, flow_info|
        current_time - flow_info[:first_seen] > @flow_timeout
      end
    end

    # Packet field extraction methods (simplified - would use actual packet parsing)
    def extract_protocol(packet)
      # Extract protocol from packet header
      [:tcp, :udp, :icmp].sample  # Simplified
    end

    def extract_source_ip(packet)
      "192.168.1.#{rand(254) + 1}"  # Simplified
    end

    def extract_destination_ip(packet)
      "10.0.0.#{rand(254) + 1}"  # Simplified
    end

    def extract_source_port(packet)
      rand(65535) + 1  # Simplified
    end

    def extract_destination_port(packet)
      [80, 443, 22, 53, 25].sample  # Simplified
    end

    def extract_packet_size(packet)
      packet.respond_to?(:bytesize) ? packet.bytesize : 1500  # Simplified
    end

    def extract_timestamp(packet)
      Time.now  # Simplified
    end

    def extract_payload_length(packet)
      rand(1000)  # Simplified
    end

    def extract_payload(packet)
      packet.respond_to?(:to_s) ? packet.to_s : ""  # Simplified
    end

    # Statistical calculation methods
    def calculate_standard_deviation(values)
      return 0 if values.empty?
      
      mean = values.sum / values.size.to_f
      variance = values.sum { |v| (v - mean) ** 2 } / values.size.to_f
      Math.sqrt(variance)
    end

    def calculate_variance(values)
      return 0 if values.empty?
      
      mean = values.sum / values.size.to_f
      values.sum { |v| (v - mean) ** 2 } / values.size.to_f
    end

    def calculate_coefficient_of_variation(values)
      return 0 if values.empty?
      
      mean = values.sum / values.size.to_f
      return 0 if mean == 0
      
      std_dev = calculate_standard_deviation(values)
      std_dev / mean
    end

    def calculate_entropy(data)
      return 0 if data.empty?
      
      frequencies = Hash.new(0)
      data.each_byte { |byte| frequencies[byte] += 1 }
      
      calculate_entropy_from_frequencies(frequencies)
    end

    def calculate_entropy_from_frequencies(frequencies)
      total = frequencies.values.sum
      return 0 if total == 0
      
      entropy = 0
      frequencies.each_value do |count|
        probability = count.to_f / total
        entropy -= probability * Math.log2(probability) if probability > 0
      end
      
      entropy
    end

    def analyze_byte_frequencies(data)
      frequencies = Hash.new(0)
      data.each_byte { |byte| frequencies[byte] += 1 }
      frequencies
    end

    def calculate_ascii_ratio(data)
      return 0 if data.empty?
      
      ascii_count = data.bytes.count { |b| b >= 32 && b <= 126 }
      ascii_count / data.bytesize.to_f
    end

    def calculate_printable_ratio(data)
      return 0 if data.empty?
      
      printable_count = data.bytes.count { |b| b >= 32 && b <= 126 }
      printable_count / data.bytesize.to_f
    end

    # Protocol-specific pattern detection
    def detect_http_patterns(payloads)
      http_keywords = ['GET ', 'POST ', 'HTTP/', 'Content-Length:', 'User-Agent:']
      payloads.sum { |p| http_keywords.count { |kw| p.include?(kw) } }
    end

    def detect_dns_patterns(payloads)
      # DNS query patterns (simplified)
      payloads.count { |p| p.bytesize > 12 && p[2].ord & 0x80 == 0 }
    end

    def detect_tls_patterns(payloads)
      # TLS handshake patterns (simplified)
      payloads.count { |p| p.start_with?("\x16\x03") }
    end

    # Temporal pattern extraction
    def extract_time_of_day_features(timestamps)
      hours = timestamps.map { |t| Time.at(t).hour }
      {
        peak_hour: hours.group_by(&:itself).max_by { |_, times| times.size }&.first,
        activity_spread: hours.uniq.size
      }
    end

    def extract_day_of_week_features(timestamps)
      days = timestamps.map { |t| Time.at(t).wday }
      {
        peak_day: days.group_by(&:itself).max_by { |_, times| times.size }&.first,
        weekday_ratio: days.count { |d| d >= 1 && d <= 5 } / days.size.to_f
      }
    end

    def identify_active_periods(timestamps)
      return [] if timestamps.size < 2
      
      gaps = timestamps.each_cons(2).map { |a, b| b - a }
      active_threshold = gaps.sum / gaps.size  # Average gap
      
      gaps.count { |gap| gap <= active_threshold }
    end

    def identify_idle_periods(timestamps)
      return [] if timestamps.size < 2
      
      gaps = timestamps.each_cons(2).map { |a, b| b - a }
      idle_threshold = gaps.sum / gaps.size * 2  # 2x average gap
      
      gaps.count { |gap| gap > idle_threshold }
    end

    def detect_periodicity(packet_sequence)
      return 0 if packet_sequence.size < 3
      
      timestamps = packet_sequence.map { |p| extract_timestamp(p) }
      gaps = timestamps.each_cons(2).map { |a, b| b - a }
      
      # Simple periodicity measure based on gap variance
      gap_variance = calculate_variance(gaps)
      gap_mean = gaps.sum / gaps.size.to_f
      
      # Lower variance relative to mean indicates more periodicity
      return 1.0 if gap_mean == 0
      1.0 - [gap_variance / gap_mean, 1.0].min
    end

    def calculate_randomness_score(packet_sequence)
      # Simplified randomness based on packet size distribution
      sizes = packet_sequence.map { |p| extract_packet_size(p) }
      return 0 if sizes.empty?
      
      entropy = calculate_entropy(sizes.pack('N*'))
      entropy / 8.0  # Normalize to 0-1 range
    end

    # TCP-specific feature extraction
    def extract_tcp_flags_distribution(tcp_packets)
      flags = tcp_packets.map { |p| extract_tcp_flags(p) }
      flags.group_by(&:itself).transform_values(&:size)
    end

    def extract_tcp_window(packet)
      rand(65535)  # Simplified
    end

    def extract_tcp_flags(packet)
      [:syn, :ack, :fin, :rst, :psh, :urg].sample  # Simplified
    end

    def extract_tcp_options_frequency(tcp_packets)
      # Simplified TCP options extraction
      { mss: rand(10), window_scale: rand(5), timestamp: rand(20) }
    end

    def extract_port_distribution(udp_packets)
      ports = udp_packets.map { |p| extract_destination_port(p) }
      ports.group_by(&:itself).transform_values(&:size)
    end

    def extract_icmp_types(icmp_packets)
      types = icmp_packets.map { |_p| rand(16) }  # Simplified
      types.group_by(&:itself).transform_values(&:size)
    end
  end

  # MlTrafficClassifier applies machine learning models to network traffic
  class MlTrafficClassifier
    attr_reader :models, :classifier_stats

    def initialize
      @models = {}
      @feature_extractor = NetworkFeatureExtractor.new
      @classifier_stats = {
        classifications_performed: 0,
        model_predictions: Hash.new(0),
        confidence_scores: [],
        processing_times: []
      }
      @mutex = Mutex.new
      
      initialize_models
    end

    # Classify network flow using ML models
    def classify_flow(packet_sequence)
      start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      
      # Extract features
      features = @feature_extractor.extract_flow_features(packet_sequence)
      
      # Run classifications
      results = {}
      
      # Protocol classification
      results[:protocol] = classify_protocol(features[:protocol_features])
      
      # Anomaly detection
      results[:anomaly] = detect_anomaly(features[:behavioral_features])
      
      # Malware detection
      results[:malware] = detect_malware(features[:payload_features])
      
      # Application identification
      results[:application] = identify_application(features)
      
      # QoS classification
      results[:qos_class] = classify_qos(features)
      
      processing_time = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start_time
      
      # Update statistics
      update_classifier_stats(results, processing_time)
      
      {
        classifications: results,
        confidence: calculate_overall_confidence(results),
        features_used: features.keys,
        processing_time_ms: (processing_time * 1000).round(2)
      }
    end

    # Classify protocol based on traffic patterns
    def classify_protocol(protocol_features)
      return { protocol: :unknown, confidence: 0.0 } if protocol_features.empty?
      
      # Rule-based classification (simplified ML model)
      if protocol_features[:tcp_flags]
        tcp_confidence = analyze_tcp_patterns(protocol_features[:tcp_flags])
        return { protocol: :tcp, confidence: tcp_confidence }
      elsif protocol_features[:udp_port_distribution]
        udp_confidence = analyze_udp_patterns(protocol_features[:udp_port_distribution])
        return { protocol: :udp, confidence: udp_confidence }
      elsif protocol_features[:icmp_types]
        return { protocol: :icmp, confidence: 0.95 }
      end
      
      { protocol: :unknown, confidence: 0.0 }
    end

    # Detect traffic anomalies
    def detect_anomaly(behavioral_features)
      return { anomaly: false, score: 0.0, type: nil } if behavioral_features.empty?
      
      anomaly_score = 0.0
      anomaly_indicators = []
      
      # Check for unusual packet rates
      if behavioral_features[:packets_per_second]
        pps = behavioral_features[:packets_per_second]
        if pps > 1000  # High packet rate threshold
          anomaly_score += 0.3
          anomaly_indicators << :high_packet_rate
        end
      end
      
      # Check for unusual byte patterns
      if behavioral_features[:size_std]
        size_cv = behavioral_features[:size_std] / [behavioral_features[:size_mean], 1].max
        if size_cv > 2.0  # High variability
          anomaly_score += 0.2
          anomaly_indicators << :irregular_sizes
        end
      end
      
      # Check for timing anomalies
      if behavioral_features[:iat_std]
        iat_cv = behavioral_features[:iat_std] / [behavioral_features[:iat_mean], 1].max
        if iat_cv > 3.0  # Very irregular timing
          anomaly_score += 0.25
          anomaly_indicators << :irregular_timing
        end
      end
      
      # Flow duration anomalies
      if behavioral_features[:flow_duration]
        duration = behavioral_features[:flow_duration]
        if duration < 0.1 || duration > 3600  # Very short or very long flows
          anomaly_score += 0.15
          anomaly_indicators << :unusual_duration
        end
      end
      
      {
        anomaly: anomaly_score > 0.5,
        score: [anomaly_score, 1.0].min,
        confidence: anomaly_score,
        indicators: anomaly_indicators
      }
    end

    # Detect potential malware traffic
    def detect_malware(payload_features)
      return { malware: false, probability: 0.0, indicators: [] } if payload_features.empty?
      
      malware_score = 0.0
      indicators = []
      
      # High entropy indicates encryption/compression (potential malware)
      if payload_features[:payload_entropy_mean]
        entropy = payload_features[:payload_entropy_mean]
        if entropy > 7.5
          malware_score += 0.3
          indicators << :high_entropy
        end
      end
      
      # Low ASCII ratio suggests binary content
      if payload_features[:ascii_ratio]
        ascii_ratio = payload_features[:ascii_ratio]
        if ascii_ratio < 0.1
          malware_score += 0.2
          indicators << :binary_content
        end
      end
      
      # Suspicious patterns
      if payload_features[:http_indicators] && payload_features[:http_indicators] == 0
        if payload_features[:payload_length_mean] && payload_features[:payload_length_mean] > 100
          malware_score += 0.15
          indicators << :non_http_large_payload
        end
      end
      
      # Zero payload ratio (potential C&C heartbeat)
      if payload_features[:zero_payload_ratio]
        if payload_features[:zero_payload_ratio] > 0.8
          malware_score += 0.2
          indicators << :mostly_empty_payloads
        end
      end
      
      {
        malware: malware_score > 0.4,
        probability: [malware_score, 1.0].min,
        confidence: malware_score,
        indicators: indicators
      }
    end

    # Identify application based on traffic patterns
    def identify_application(features)
      # Application identification based on multiple feature types
      app_scores = {}
      
      # Web traffic detection
      if features[:payload_features][:http_indicators] && features[:payload_features][:http_indicators] > 0
        app_scores[:web_browser] = 0.8
      end
      
      # DNS traffic detection
      if features[:payload_features][:dns_indicators] && features[:payload_features][:dns_indicators] > 0
        app_scores[:dns_client] = 0.9
      end
      
      # Email traffic patterns
      if features[:protocol_features][:dominant_protocol] == :tcp
        tcp_ports = features[:protocol_features][:udp_port_distribution] || {}
        if tcp_ports[25] || tcp_ports[587] || tcp_ports[993]
          app_scores[:email_client] = 0.85
        end
      end
      
      # P2P traffic patterns
      if features[:behavioral_features][:bidirectional_packets]
        bidirectional_ratio = features[:behavioral_features][:bidirectional_packets] / 
                             [features[:behavioral_features][:forward_packets], 1].max
        if bidirectional_ratio > 0.7
          app_scores[:p2p_application] = 0.6
        end
      end
      
      # File transfer patterns
      if features[:behavioral_features][:bytes_per_second] && features[:behavioral_features][:bytes_per_second] > 1_000_000
        app_scores[:file_transfer] = 0.7
      end
      
      # Return highest scoring application
      best_app = app_scores.max_by { |_, score| score }
      
      if best_app
        { application: best_app[0], confidence: best_app[1] }
      else
        { application: :unknown, confidence: 0.0 }
      end
    end

    # Classify traffic for QoS purposes
    def classify_qos(features)
      # QoS classification based on application and behavior
      
      # Real-time applications (high priority)
      if features[:temporal_features][:flow_duration] && features[:temporal_features][:flow_duration] < 10
        if features[:behavioral_features][:packet_count] && features[:behavioral_features][:packet_count] > 100
          return { qos_class: :real_time, priority: :high, confidence: 0.8 }
        end
      end
      
      # Interactive applications (medium-high priority)
      if features[:behavioral_features][:iat_mean] && features[:behavioral_features][:iat_mean] < 0.1
        return { qos_class: :interactive, priority: :medium_high, confidence: 0.7 }
      end
      
      # Bulk transfer (low priority)
      if features[:behavioral_features][:bytes_per_second] && features[:behavioral_features][:bytes_per_second] > 10_000_000
        return { qos_class: :bulk, priority: :low, confidence: 0.9 }
      end
      
      # Default best effort
      { qos_class: :best_effort, priority: :medium, confidence: 0.5 }
    end

    # Get classification statistics
    def classification_stats
      @mutex.synchronize do
        avg_confidence = @classifier_stats[:confidence_scores].empty? ? 0 : 
                        (@classifier_stats[:confidence_scores].sum / @classifier_stats[:confidence_scores].size)
        
        avg_processing_time = @classifier_stats[:processing_times].empty? ? 0 :
                             (@classifier_stats[:processing_times].sum / @classifier_stats[:processing_times].size)
        
        {
          total_classifications: @classifier_stats[:classifications_performed],
          model_usage: @classifier_stats[:model_predictions],
          average_confidence: avg_confidence.round(3),
          average_processing_time_ms: (avg_processing_time * 1000).round(2),
          feature_extractor_stats: @feature_extractor.extraction_stats
        }
      end
    end

    private

    def initialize_models
      # In a real implementation, these would load actual ML models
      @models = {
        protocol_classifier: :rule_based,
        anomaly_detector: :statistical,
        malware_detector: :heuristic,
        application_classifier: :pattern_matching,
        qos_classifier: :behavioral
      }
    end

    def update_classifier_stats(results, processing_time)
      @mutex.synchronize do
        @classifier_stats[:classifications_performed] += 1
        @classifier_stats[:processing_times] << processing_time
        
        results.each do |model, result|
          @classifier_stats[:model_predictions][model] += 1
          if result.is_a?(Hash) && result[:confidence]
            @classifier_stats[:confidence_scores] << result[:confidence]
          end
        end
        
        # Keep only recent samples for moving averages
        if @classifier_stats[:confidence_scores].size > 1000
          @classifier_stats[:confidence_scores].shift(500)
        end
        
        if @classifier_stats[:processing_times].size > 1000
          @classifier_stats[:processing_times].shift(500)
        end
      end
    end

    def calculate_overall_confidence(results)
      confidences = results.values.map do |result|
        if result.is_a?(Hash)
          result[:confidence] || result[:score] || result[:probability] || 0.0
        else
          0.0
        end
      end
      
      return 0.0 if confidences.empty?
      confidences.sum / confidences.size
    end

    def analyze_tcp_patterns(tcp_flags)
      # Analyze TCP flag distribution for protocol confidence
      syn_count = tcp_flags[:syn] || 0
      ack_count = tcp_flags[:ack] || 0
      total_packets = tcp_flags.values.sum
      
      return 0.0 if total_packets == 0
      
      # Normal TCP should have balanced SYN/ACK patterns
      syn_ratio = syn_count.to_f / total_packets
      ack_ratio = ack_count.to_f / total_packets
      
      if syn_ratio > 0.01 && ack_ratio > 0.1  # Typical TCP conversation
        0.9
      elsif syn_ratio > 0.5  # Possible SYN flood
        0.7
      else
        0.8
      end
    end

    def analyze_udp_patterns(port_distribution)
      # Analyze UDP port patterns
      common_udp_ports = [53, 67, 68, 69, 123, 161, 162]
      
      common_port_traffic = port_distribution.select { |port, _| common_udp_ports.include?(port) }
      total_traffic = port_distribution.values.sum
      
      if common_port_traffic.any? && total_traffic > 0
        common_ratio = common_port_traffic.values.sum.to_f / total_traffic
        0.6 + (common_ratio * 0.3)  # 0.6 to 0.9 confidence
      else
        0.5  # Unknown UDP traffic
      end
    end
  end
end
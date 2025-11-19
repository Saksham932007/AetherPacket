# frozen_string_literal: true

require 'webrick'
require 'json'
require 'erb'

module AetherPacket
  # HTTPApiServer provides RESTful API access to network appliance data
  class HTTPApiServer
    attr_reader :server, :port, :host, :running

    def initialize(appliance:, port: 8080, host: '0.0.0.0', enable_cors: true)
      @appliance = appliance
      @port = port
      @host = host
      @enable_cors = enable_cors
      @running = false
      @server = nil
      @mutex = Mutex.new
      @request_count = 0
      @start_time = Time.now
    end

    # Start the HTTP API server
    def start!
      @mutex.synchronize do
        return if @running
        
        @server = WEBrick::HTTPServer.new(
          Port: @port,
          BindAddress: @host,
          Logger: WEBrick::Log.new('/dev/null'),
          AccessLog: []
        )
        
        setup_routes
        @running = true
      end
      
      Thread.new { @server.start }
      puts "AetherPacket API server started on http://#{@host}:#{@port}"
    end

    # Stop the HTTP API server
    def stop!
      @mutex.synchronize do
        if @server && @running
          @server.shutdown
          @server = nil
          @running = false
          puts "AetherPacket API server stopped"
        end
      end
    end

    # Check if server is running
    def running?
      @mutex.synchronize { @running }
    end

    private

    def setup_routes
      # API status endpoint
      @server.mount_proc '/api/status' do |req, res|
        handle_request(req, res) { api_status }
      end
      
      # Network metrics endpoints
      @server.mount_proc '/api/metrics' do |req, res|
        handle_request(req, res) { get_metrics }
      end
      
      @server.mount_proc '/api/metrics/dashboard' do |req, res|
        handle_request(req, res) { get_dashboard_data }
      end
      
      # Security endpoints
      @server.mount_proc '/api/security/firewall' do |req, res|
        handle_request(req, res) { get_firewall_stats }
      end
      
      @server.mount_proc '/api/security/ids' do |req, res|
        handle_request(req, res) { get_ids_stats }
      end
      
      @server.mount_proc '/api/security/sinkhole' do |req, res|
        handle_request(req, res) { get_sinkhole_stats }
      end
      
      # Network appliance endpoints
      @server.mount_proc '/api/appliance/status' do |req, res|
        handle_request(req, res) { get_appliance_status }
      end
      
      @server.mount_proc '/api/appliance/interfaces' do |req, res|
        handle_request(req, res) { get_interface_stats }
      end
      
      @server.mount_proc '/api/appliance/nat' do |req, res|
        handle_request(req, res) { get_nat_stats }
      end
      
      # Configuration endpoints
      @server.mount_proc '/api/config/firewall' do |req, res|
        handle_config_request(req, res, :firewall)
      end
      
      # Dashboard HTML endpoint
      @server.mount_proc '/dashboard' do |req, res|
        serve_dashboard(req, res)
      end
      
      # Static assets
      @server.mount_proc '/' do |req, res|
        if req.path == '/'
          res.status = 302
          res['Location'] = '/dashboard'
        else
          res.status = 404
          res.body = 'Not Found'
        end
      end
    end

    def handle_request(req, res, &block)
      @mutex.synchronize { @request_count += 1 }
      
      # Enable CORS if configured
      if @enable_cors
        res['Access-Control-Allow-Origin'] = '*'
        res['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        res['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
      end
      
      # Handle OPTIONS preflight
      if req.request_method == 'OPTIONS'
        res.status = 204
        return
      end
      
      begin
        data = yield
        res['Content-Type'] = 'application/json'
        res.body = JSON.pretty_generate(data)
      rescue => e
        res.status = 500
        res['Content-Type'] = 'application/json'
        res.body = JSON.generate({ error: e.message, type: e.class.name })
      end
    end

    def handle_config_request(req, res, component)
      case req.request_method
      when 'GET'
        handle_request(req, res) { get_component_config(component) }
      when 'POST'
        handle_request(req, res) { update_component_config(component, req) }
      else
        res.status = 405
        res.body = 'Method Not Allowed'
      end
    end

    # API endpoint handlers
    def api_status
      {
        status: 'running',
        version: AetherPacket::VERSION,
        uptime_seconds: (Time.now - @start_time).to_i,
        request_count: @request_count,
        timestamp: Time.now.iso8601
      }
    end

    def get_metrics
      if @appliance.respond_to?(:metrics)
        @appliance.metrics.metrics_summary
      else
        { error: 'Metrics not available' }
      end
    end

    def get_dashboard_data
      dashboard_data = {}
      
      # Network metrics
      if @appliance.respond_to?(:metrics)
        dashboard_data[:metrics] = @appliance.metrics.dashboard_data
      end
      
      # Security status
      dashboard_data[:security] = {
        firewall: get_firewall_summary,
        ids: get_ids_summary,
        sinkhole: get_sinkhole_summary
      }
      
      # System status
      dashboard_data[:system] = {
        appliance_status: get_appliance_summary,
        interfaces: get_interface_summary
      }
      
      dashboard_data
    end

    def get_firewall_stats
      if @appliance.respond_to?(:firewall)
        @appliance.firewall.firewall_stats
      else
        { error: 'Firewall not available' }
      end
    end

    def get_ids_stats
      if @appliance.respond_to?(:ids_controller)
        @appliance.ids_controller.ids_stats
      else
        { error: 'IDS not available' }
      end
    end

    def get_sinkhole_stats
      if @appliance.respond_to?(:dns_sinkhole)
        @appliance.dns_sinkhole.sinkhole_stats
      else
        { error: 'DNS sinkhole not available' }
      end
    end

    def get_appliance_status
      {
        running: @appliance.respond_to?(:running?) ? @appliance.running? : false,
        interfaces: @appliance.respond_to?(:interfaces) ? @appliance.interfaces.keys : [],
        components: get_component_status
      }
    end

    def get_interface_stats
      if @appliance.respond_to?(:interfaces)
        @appliance.interfaces.transform_values do |interface|
          {
            name: interface.name,
            type: interface.respond_to?(:interface_type) ? interface.interface_type : 'unknown',
            status: interface.respond_to?(:status) ? interface.status : 'unknown'
          }
        end
      else
        {}
      end
    end

    def get_nat_stats
      if @appliance.respond_to?(:nat_engine)
        @appliance.nat_engine.translation_stats
      else
        { error: 'NAT engine not available' }
      end
    end

    def get_component_config(component)
      case component
      when :firewall
        if @appliance.respond_to?(:firewall)
          @appliance.firewall.export_rules
        else
          { error: 'Firewall not available' }
        end
      else
        { error: 'Component not supported' }
      end
    end

    def update_component_config(component, req)
      # Parse JSON body
      config_data = JSON.parse(req.body || '{}')
      
      case component
      when :firewall
        if @appliance.respond_to?(:firewall)
          # Would implement firewall config updates here
          { success: true, message: 'Configuration update not implemented' }
        else
          { error: 'Firewall not available' }
        end
      else
        { error: 'Component not supported' }
      end
    end

    # Summary helpers
    def get_firewall_summary
      if @appliance.respond_to?(:firewall)
        stats = @appliance.firewall.firewall_stats
        {
          enabled: stats[:enabled] || false,
          rules_count: stats[:total_rules] || 0,
          packets_blocked: stats[:packets_blocked] || 0
        }
      else
        { enabled: false, error: 'Not available' }
      end
    end

    def get_ids_summary
      if @appliance.respond_to?(:ids_controller)
        stats = @appliance.ids_controller.ids_stats
        {
          enabled: stats[:controller_enabled] || false,
          alerts_count: stats[:alert_buffer_size] || 0,
          detection_rate: stats[:detection_rate_percent] || 0
        }
      else
        { enabled: false, error: 'Not available' }
      end
    end

    def get_sinkhole_summary
      if @appliance.respond_to?(:dns_sinkhole)
        stats = @appliance.dns_sinkhole.sinkhole_stats
        {
          enabled: stats[:enabled] || false,
          blocked_domains: stats[:unique_sinkholed_domains] || 0,
          sinkhole_rate: stats[:sinkhole_rate] || 0
        }
      else
        { enabled: false, error: 'Not available' }
      end
    end

    def get_appliance_summary
      {
        running: @appliance.respond_to?(:running?) ? @appliance.running? : false,
        interface_count: @appliance.respond_to?(:interfaces) ? @appliance.interfaces.size : 0
      }
    end

    def get_interface_summary
      if @appliance.respond_to?(:interfaces)
        {
          total: @appliance.interfaces.size,
          active: @appliance.interfaces.values.count { |iface| 
            iface.respond_to?(:status) && iface.status == 'active'
          }
        }
      else
        { total: 0, active: 0 }
      end
    end

    def get_component_status
      components = {}
      
      components[:firewall] = @appliance.respond_to?(:firewall)
      components[:nat_engine] = @appliance.respond_to?(:nat_engine)
      components[:ids_controller] = @appliance.respond_to?(:ids_controller)
      components[:dns_sinkhole] = @appliance.respond_to?(:dns_sinkhole)
      components[:traffic_shaper] = @appliance.respond_to?(:traffic_shaper)
      components[:metrics] = @appliance.respond_to?(:metrics)
      
      components
    end

    def serve_dashboard(req, res)
      res['Content-Type'] = 'text/html'
      res.body = generate_dashboard_html
    end

    def generate_dashboard_html
      <<~HTML
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>AetherPacket Network Appliance Dashboard</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
                .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
                .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
                .card { background: white; border-radius: 5px; padding: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
                .card h3 { margin-top: 0; color: #2c3e50; border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; }
                .metric { display: flex; justify-content: space-between; margin: 10px 0; padding: 5px 0; }
                .metric-label { font-weight: bold; }
                .metric-value { color: #27ae60; }
                .status-indicator { display: inline-block; width: 12px; height: 12px; border-radius: 50%; margin-right: 5px; }
                .status-ok { background: #27ae60; }
                .status-warning { background: #f39c12; }
                .status-error { background: #e74c3c; }
                .refresh-btn { background: #3498db; color: white; border: none; padding: 10px 20px; border-radius: 3px; cursor: pointer; }
                .api-links { margin-top: 20px; }
                .api-links a { display: inline-block; margin-right: 10px; color: #3498db; text-decoration: none; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🌐 AetherPacket Network Appliance</h1>
                <p>Enterprise-grade userspace network appliance dashboard</p>
                <button class="refresh-btn" onclick="refreshDashboard()">Refresh Data</button>
            </div>
            
            <div class="dashboard" id="dashboard">
                <div class="card">
                    <h3>Loading...</h3>
                    <p>Fetching dashboard data...</p>
                </div>
            </div>
            
            <div class="api-links">
                <h3>API Endpoints:</h3>
                <a href="/api/status" target="_blank">/api/status</a>
                <a href="/api/metrics" target="_blank">/api/metrics</a>
                <a href="/api/metrics/dashboard" target="_blank">/api/metrics/dashboard</a>
                <a href="/api/security/firewall" target="_blank">/api/security/firewall</a>
                <a href="/api/appliance/status" target="_blank">/api/appliance/status</a>
            </div>
            
            <script>
                async function fetchDashboardData() {
                    try {
                        const response = await fetch('/api/metrics/dashboard');
                        const data = await response.json();
                        updateDashboard(data);
                    } catch (error) {
                        console.error('Failed to fetch dashboard data:', error);
                        document.getElementById('dashboard').innerHTML = 
                            '<div class="card"><h3>Error</h3><p>Failed to load dashboard data</p></div>';
                    }
                }
                
                function updateDashboard(data) {
                    const dashboard = document.getElementById('dashboard');
                    
                    let html = '';
                    
                    // Network Metrics Card
                    if (data.metrics && data.metrics.network) {
                        html += generateNetworkCard(data.metrics.network);
                    }
                    
                    // Security Card
                    if (data.security) {
                        html += generateSecurityCard(data.security);
                    }
                    
                    // System Card
                    if (data.system) {
                        html += generateSystemCard(data.system);
                    }
                    
                    dashboard.innerHTML = html;
                }
                
                function generateNetworkCard(network) {
                    return `
                        <div class="card">
                            <h3>📊 Network Performance</h3>
                            <div class="metric">
                                <span class="metric-label">Packets/sec:</span>
                                <span class="metric-value">${(network.packets_per_second || 0).toFixed(1)}</span>
                            </div>
                            <div class="metric">
                                <span class="metric-label">Bytes/sec:</span>
                                <span class="metric-value">${formatBytes(network.bytes_per_second || 0)}</span>
                            </div>
                            <div class="metric">
                                <span class="metric-label">Utilization:</span>
                                <span class="metric-value">${(network.utilization?.total_utilization_percent || 0).toFixed(2)}%</span>
                            </div>
                        </div>
                    `;
                }
                
                function generateSecurityCard(security) {
                    return `
                        <div class="card">
                            <h3>🛡️ Security Status</h3>
                            <div class="metric">
                                <span class="metric-label">Firewall:</span>
                                <span class="status-indicator ${security.firewall?.enabled ? 'status-ok' : 'status-error'}"></span>
                                <span class="metric-value">${security.firewall?.packets_blocked || 0} blocked</span>
                            </div>
                            <div class="metric">
                                <span class="metric-label">IDS:</span>
                                <span class="status-indicator ${security.ids?.enabled ? 'status-ok' : 'status-error'}"></span>
                                <span class="metric-value">${security.ids?.alerts_count || 0} alerts</span>
                            </div>
                            <div class="metric">
                                <span class="metric-label">DNS Sinkhole:</span>
                                <span class="status-indicator ${security.sinkhole?.enabled ? 'status-ok' : 'status-error'}"></span>
                                <span class="metric-value">${security.sinkhole?.blocked_domains || 0} domains</span>
                            </div>
                        </div>
                    `;
                }
                
                function generateSystemCard(system) {
                    return `
                        <div class="card">
                            <h3>⚙️ System Status</h3>
                            <div class="metric">
                                <span class="metric-label">Appliance:</span>
                                <span class="status-indicator ${system.appliance_status?.running ? 'status-ok' : 'status-error'}"></span>
                                <span class="metric-value">${system.appliance_status?.running ? 'Running' : 'Stopped'}</span>
                            </div>
                            <div class="metric">
                                <span class="metric-label">Interfaces:</span>
                                <span class="metric-value">${system.interfaces?.active || 0}/${system.interfaces?.total || 0} active</span>
                            </div>
                        </div>
                    `;
                }
                
                function formatBytes(bytes) {
                    if (bytes === 0) return '0 B/s';
                    const k = 1024;
                    const sizes = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
                    const i = Math.floor(Math.log(bytes) / Math.log(k));
                    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
                }
                
                function refreshDashboard() {
                    fetchDashboardData();
                }
                
                // Initial load
                fetchDashboardData();
                
                // Auto-refresh every 5 seconds
                setInterval(fetchDashboardData, 5000);
            </script>
        </body>
        </html>
      HTML
    end
  end

  # DashboardManager coordinates HTTP API server with network appliance
  class DashboardManager
    attr_reader :api_server, :enabled

    def initialize(appliance:, **server_options)
      @api_server = HTTPApiServer.new(appliance: appliance, **server_options)
      @enabled = false
      @mutex = Mutex.new
    end

    # Start dashboard server
    def start!
      @mutex.synchronize do
        return if @enabled
        
        @api_server.start!
        @enabled = true
      end
    end

    # Stop dashboard server
    def stop!
      @mutex.synchronize do
        return unless @enabled
        
        @api_server.stop!
        @enabled = false
      end
    end

    # Get dashboard status
    def dashboard_status
      {
        enabled: @enabled,
        running: @api_server.running?,
        port: @api_server.port,
        host: @api_server.host
      }
    end

    # Get dashboard URL
    def dashboard_url
      return nil unless @enabled && @api_server.running?
      "http://#{@api_server.host}:#{@api_server.port}/dashboard"
    end
  end
end
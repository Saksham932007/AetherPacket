# frozen_string_literal: true

source "https://rubygems.org"

git_source(:github) { |repo| "https://github.com/#{repo}.git" }

ruby "~> 3.0"

# Core dependencies - minimal by design
gem "fiddle", "~> 1.1"  # For ioctl system calls
gem "bindata", "~> 2.4" # For binary data parsing

group :development, :test do
  gem "rspec", "~> 3.0"
  gem "rubocop", "~> 1.0"
  gem "benchmark-ips", "~> 2.0"
end

group :test do
  gem "simplecov", "~> 0.21"
end
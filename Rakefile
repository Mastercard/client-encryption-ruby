# frozen_string_literal: true

require 'rubygems'
require 'rake'
require 'rake/clean'
require 'rake/testtask'

desc 'Run tests'
task default: 'test'
Rake::TestTask.new do |t|
  t.libs << 'test'
  t.test_files = FileList['test/test_*.rb']
  # Load SimpleCov before starting the tests
  t.ruby_opts = ['-r "./test/test_helper"']
  t.verbose = true
  t.warning = false
end

Dir['tasks/**/*.rake'].each { |t| load t }

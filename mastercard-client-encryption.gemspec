# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name = 'mastercard-client-encryption'
  spec.version = '1.3.2'
  spec.authors = ['Mastercard']
  spec.required_ruby_version = '>= 2.4.4'

  spec.summary = 'Mastercard encryption library'
  spec.description = 'Library for Mastercard API compliant payload encryption/decryption.'
  spec.homepage = 'https://github.com/Mastercard/client-encryption-ruby'
  spec.license = 'MIT'

  spec.files = Dir['{lib}/**/*']
  spec.require_paths = ['lib']

  spec.add_dependency "hamster"

  spec.add_development_dependency 'bundler', '>= 1.5'
  spec.add_development_dependency 'minitest', '~> 5.0'
  spec.add_development_dependency 'rake', '>= 12.3.3'
  spec.add_development_dependency 'simplecov', '~> 0.16.1'
end

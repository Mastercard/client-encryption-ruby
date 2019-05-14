# frozen_string_literal: true

require 'minitest/autorun'
require 'minitest/mock'
require_relative '../lib/mcapi/encryption/crypto/crypto'
require_relative './utils'
require 'json'

class TestCryptoConfig < Minitest::Test
  def setup
    @test_config = JSON.parse(File.read('./test/mock/config.json'))
    @crypto = McAPI::Encryption::Crypto.new(@test_config)
  end

  def test_config_is_nil
    assert_equal(assert_raises(Exception) do
      McAPI::Encryption::Crypto.new(nil)
    end.message, 'Config not valid: config should be an Hash.')
  end

  def test_config_is_not_hash
    assert_equal(assert_raises(Exception) do
      McAPI::Encryption::Crypto.new('')
    end.message, 'Config not valid: config should be an Hash.')
  end

  def test_config_is_hash
    assert_equal(assert_raises(Exception) do
      McAPI::Encryption::Crypto.new({})
    end.message, 'Config not valid: paths should be an array of path element.')
  end

  def test_config_all_props_defined
    assert !@crypto.nil?
  end

  def test_fingerprint_public_key_ok
    config = @test_config.dup
    config['encryptionCertificate'] = './test/res/pub_cert_0.pem'
    crypto = McAPI::Encryption::Crypto.new(config)
    fingerprint = crypto.send :compute_public_fingerprint, 'publicKey'
    assert_equal '4bf20ad3389076f6404d37f0efef488eebe2304ea48d0aa0b6b372ab9b5f0f9d', fingerprint
    config['dataEncoding'] = 'base64'
    crypto = McAPI::Encryption::Crypto.new(config)
    fingerprint = crypto.send :compute_public_fingerprint, 'publicKey'
    assert_equal '4bf20ad3389076f6404d37f0efef488eebe2304ea48d0aa0b6b372ab9b5f0f9d', fingerprint
  end

  def test_fingerprint_public_certificate_ok
    config = @test_config.dup
    config['encryptionCertificate'] = './test/res/pub_cert_1.pem'
    crypto = McAPI::Encryption::Crypto.new(config)
    fingerprint = crypto.send :compute_public_fingerprint, 'certificate'
    assert_equal '67e80e19b8a50da945726e32672623d69aff375a9d83c4181026ec4efbb7c800', fingerprint
  end

  def test_fingerprint_public_certificate_ok__b64
    config = @test_config.dup
    config['dataEncoding'] = 'base64'
    config['encryptionCertificate'] = './test/res/pub_cert_1.pem'
    crypto = McAPI::Encryption::Crypto.new(config)
    fingerprint = crypto.send :compute_public_fingerprint, 'certificate'
    assert_equal 'Z+gOGbilDalFcm4yZyYj1pr/N1qdg8QYECbsTvu3yAA=', fingerprint
  end

  def test_config_with_private_keystore
    config = @test_config.dup
    config.delete('privateKey')
    config['keyStore'] = './test/res/test_key.p12'
    config['keyStoreAlias'] = 'mykeyalias'
    config['keyStorePassword'] = 'Password1'
    crypto = McAPI::Encryption::Crypto.new(config)
    assert(crypto)
  end

  def test_fingerprint_wrong_type
    crypto = McAPI::Encryption::Crypto.new(@test_config)
    assert_exp_equals(RuntimeError, 'Selected public fingerprint not supported') do
      crypto.send :compute_public_fingerprint, 'wrongtype'
    end
  end
end

# frozen_string_literal: true

require 'minitest/autorun'
require 'minitest/mock'
require_relative '../lib/mcapi/encryption/jwe_encryption'
require_relative '../lib/mcapi/encryption/utils/utils'
require 'json'

class TestJweEncryption < Minitest::Test
  def setup
    @test_config = JSON.parse(File.read('./test/mock/jwe-config.json'))
  end

  def test_encrypt_field_level
    request = JSON.generate(
      {
        "mapping": {
          "customer_identifier": "CUST_12345",
          "customer_name": {
            "first_name": "John",
            "last_name": "Doe"
          }
        }
      }
    )

    jwe = McAPI::Encryption::JweEncryption.new(@test_config)
    res = jwe.encrypt('/mappings', request)
    assert res
    assert res[:body]['encrypted_payload']['encrypted_data']
    assert !res[:body]['mapping']['customer_identifier']
  end

  def test_encrypt_full_payload
    request = JSON.generate(
      {
        "mapping": {
          "customer_identifier": "CUST_12345",
          "customer_name": {
            "first_name": "John",
            "last_name": "Doe"
          }
        }
      }
    )

    jwe = McAPI::Encryption::JweEncryption.new(@test_config)
    res = jwe.encrypt('/resource', request)
    assert res
    assert res[:body]['encrypted_data']
    assert !res[:body]['mapping']
  end

  def test_encrypt_decrypt_root_array
    jwe = McAPI::Encryption::JweEncryption.new(@test_config)
    request = JSON.generate([{}, []])

    res = jwe.encrypt('/arrays', request)

    resp = JSON.generate(request: { url: '/arrays' }, body: res[:body])
    decrypted_resp = JSON.parse(jwe.decrypt(resp))

    assert_equal JSON.generate(decrypted_resp['body']), request
  end

  def test_encrypt_config_not_found
    jwe = McAPI::Encryption::JweEncryption.new(@test_config)
    request = JSON.generate(
      elem1: {
        encryptedData: {
          accountNumber: '5123456789012345'
        }
      }
    )
    res = jwe.encrypt('/not-exists', request)
    assert_nil res[:header]
    assert_equal request, JSON.generate(res[:body])
  end

  def test_decrypt_field_level
    resp = File.read('./test/mock/jwe-response.json')
    jwe = McAPI::Encryption::JweEncryption.new(@test_config)
    decrypted = JSON.parse(jwe.decrypt(resp))
    assert_equal decrypted['body']['mapping']['customer_identifier'], 'CUST_12345'
    assert !decrypted['body']['encrypted_payload']
  end

  def test_decrypt_gcm
    resp = File.read('./test/mock/jwe-response-gcm.json')
    jwe = McAPI::Encryption::JweEncryption.new(@test_config)
    decrypted = JSON.parse(jwe.decrypt(resp))
    assert_equal decrypted['body']['mapping']['customer_identifier'], 'CUST_12345'
    assert !decrypted['body']['encrypted_data']
  end

  def test_decrypt_cbc
    resp = File.read('./test/mock/jwe-response-cbc.json')
    jwe = McAPI::Encryption::JweEncryption.new(@test_config)
    decrypted = JSON.parse(jwe.decrypt(resp))
    assert !decrypted['body']['encrypted_data']
  end
end

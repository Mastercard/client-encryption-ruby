# frozen_string_literal: true

require 'minitest/autorun'
require 'minitest/mock'
require_relative '../lib/mcapi/encryption/field_level_encryption'
require 'json'

class TestFieldLevelEncryption < Minitest::Test
  def setup
    @test_config = JSON.parse(File.read('./test/mock/config.json'))
    @test_config_with_header = JSON.parse(File.read('./test/mock/config-header.json'))
    @config_readme = JSON.parse(File.read('./test/mock/config-readme.json'))
  end

  def test_encrypt
    fle = McAPI::Encryption::FieldLevelEncryption.new(@test_config)
    request = JSON.generate(
      elem1: {
          encryptedData: {
              accountNumber: '5123456789012345'
          },
          shouldBeThere: "here I'am"
      }
    )

    res = fle.encrypt('/resource?q=foobar', nil, request)
    assert res[:header].nil?
    assert res[:body]['elem1']['encryptedData']
    assert res[:body]['elem1']['shouldBeThere']
    assert res[:body]['elem1']['encryptedKey']
    assert res[:body]['elem1']['iv']
    assert res[:body]['elem1']['oaepHashingAlgorithm']
    assert res[:body]['elem1']['publicKeyFingerprint']
    assert !res[:body]['elem1']['encryptedData']['accountNumber']
  end

  def test_encrypt_with_header
    fle = McAPI::Encryption::FieldLevelEncryption.new(@test_config_with_header)
    request = JSON.generate(
      encrypted_payload: {
          data: {
              accountNumber: '5123456789012345'
          }
      }
    )
    header = {}
    res = fle.encrypt('/resource', header, request)
    assert_equal res[:header], header
    assert header[@test_config_with_header['encryptedKeyHeaderName']]
    assert header[@test_config_with_header['ivHeaderName']]
    assert header[@test_config_with_header['oaepHashingAlgorithmHeaderName']]
    assert header[@test_config_with_header['publicKeyFingerprintHeaderName']]
    assert_equal res[:body]['encrypted_payload']['data'].length, 160
  end

  def test_encrypt_config_not_found
    fle = McAPI::Encryption::FieldLevelEncryption.new(@test_config)
    request = JSON.generate(
      elem1: {
          encryptedData: {
              accountNumber: '5123456789012345'
          }
      }
    )
    res = fle.encrypt('/not-exists', nil, request)
    assert_nil res[:header]
    assert_equal request, JSON.generate(res[:body])
  end

  def test_decrypt
    resp = File.read('./test/mock/response.json')
    fle = McAPI::Encryption::FieldLevelEncryption.new(@test_config)
    decrypted = JSON.parse(fle.decrypt(resp))
    assert_equal decrypted['body']['foo']['accountNumber'], '5123456789012345'
    assert !decrypted['body']['foo']['elem1']
    assert !decrypted['body']['foo']['encryptedData']
  end

  def test_decrypt_response_replacing_whole_body
    resp = File.read('./test/mock/response-root.json')
    config = @test_config.dup
    config['paths'][0]['toDecrypt'][0]['obj'] = 'encryptedData'
    config['paths'][0]['toDecrypt'][0]['element'] = ''
    fle = McAPI::Encryption::FieldLevelEncryption.new(config)
    decrypted = JSON.parse(fle.decrypt(resp))
    assert_equal decrypted['body']['encryptedData']['accountNumber'], '5123456789012345'
    assert decrypted['body']['notDelete']
  end

  def test_decrypt_with_header
    resp = File.read('./test/mock/response-header.json')
    fle = McAPI::Encryption::FieldLevelEncryption.new(@test_config_with_header)
    decrypted = JSON.parse(fle.decrypt(resp))
    assert_equal decrypted['body']['encrypted_payload']['data']['accountNumber'], '5123456789012345'
  end

  def test_decrypt_node_not_found_in_body
    resp = File.read('./test/mock/response-header.json')
    fle = McAPI::Encryption::FieldLevelEncryption.new(@test_config_with_header)
    resp_hash = JSON.parse(resp)
    resp_hash['body'].delete('encrypted_payload')
    resp_hash['body'] = JSON.parse(JSON.generate(test: 'foo'))
    resp_hash = JSON.generate(resp_hash)
    decrypted = JSON.parse(fle.decrypt(resp_hash))
    assert_equal decrypted['body']['test'], 'foo'
  end

  def test_decrypt_without_config
    fle = McAPI::Encryption::FieldLevelEncryption.new(@test_config)
    response = JSON.generate(request: { url: '/foobar' }, body: 'abc')
    assert_equal JSON.parse(fle.decrypt(response))['body'], 'abc'
  end

  def test_elem_from_path_valid_path
    fle = McAPI::Encryption::FieldLevelEncryption.new(@test_config)
    res = fle.send :elem_from_path, 'elem1.elem2', JSON.parse(JSON.generate(elem1: { elem2: 'test' }))
    assert_equal res[:node], 'test'
    assert_equal res[:parent], JSON.parse(JSON.generate(elem2: 'test'))
  end

  def test_elem_from_path_not_valid_path
    fle = McAPI::Encryption::FieldLevelEncryption.new(@test_config)
    res = fle.send :elem_from_path, 'elem1.elem2', JSON.parse(JSON.generate(elem2: 'test'))
    assert_nil res
  end

  def test_encrypt_body_payload_with_readme_config
    fle = McAPI::Encryption::FieldLevelEncryption.new(@config_readme)
    request = JSON.generate(
      path: {
          to: {
              encryptedData: {
                  sensitive: 'this is a secret',
                  sensitive2: 'this is a super secret!'
              }
          }
      }
    )
    res = fle.encrypt('/resource', nil, request)
    assert res[:header].nil?
    assert res[:body]['path']
    assert res[:body]['path']['to']
    assert res[:body]['path']['to']['encryptedData']
    assert !res[:body]['path']['to']['encryptedData']['sensitive']
    assert !res[:body]['path']['to']['encryptedData']['sensitive2']
    assert res[:body]['path']['to']['iv']
    assert res[:body]['path']['to']['encryptedKey']
    assert res[:body]['path']['to']['oaepHashingAlgorithm']
    assert res[:body]['path']['to']['publicKeyFingerprint']
  end

  def test_decrypt_response_with_readme_config
    fle = McAPI::Encryption::FieldLevelEncryption.new(@config_readme)
    resp = File.read('./test/mock/response-readme.json')
    decrypted = JSON.parse(fle.decrypt(resp))
    assert decrypted['body']['path']
    assert decrypted['body']['path']['to']['foo']
    assert decrypted['body']['path']['to']['foo']['sensitive']
    assert decrypted['body']['path']['to']['foo']['sensitive2']
    assert_equal decrypted['body']['path']['to']['foo']['sensitive'], 'this is a secret'
    assert_equal decrypted['body']['path']['to']['foo']['sensitive2'], 'this is a super secret!'
  end
end

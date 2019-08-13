# frozen_string_literal: true

require 'minitest/autorun'
require 'minitest/mock'
require_relative '../lib/mcapi/encryption/field_level_encryption'
require 'json'

class TestPayloadEncryption < Minitest::Test
  def setup
    @test_config = JSON.parse(File.read('./test/mock/config.json'))
    @test_config['encryptedValueFieldName'] = 'encryptedValue'
  end

  def test_encrypt_with_sibling
    fle = McAPI::Encryption::FieldLevelEncryption.new(@test_config)
    body = JSON.parse(JSON.generate(
                        data: {
                            field1: 'value1',
                            field2: 'value2'
                        },
                        encryptedData: {}
                      ))
    fle.send :encrypt_with_body, JSON.parse(JSON.generate(element: 'data', obj: 'encryptedData')), body
    # puts JSON.pretty_generate(body)
    assert !body['data']
    assert body['encryptedData']
    assert body['encryptedData']['encryptedValue']
    assert body['encryptedData']['iv']
    assert body['encryptedData']['encryptedKey']
    assert body['encryptedData']['publicKeyFingerprint']
    assert body['encryptedData']['oaepHashingAlgorithm']
  end

  def test_encrypt_dest_obj_not_exists
    fle = McAPI::Encryption::FieldLevelEncryption.new(@test_config)
    body = JSON.parse(JSON.generate(
                        itemsToEncrypt: {
                            first: 'first',
                            second: 'second'
                        },
                        dontEncrypt: {
                            text: 'just text...'
                        }
                      ))
    fle.send :encrypt_with_body, JSON.parse(JSON.generate(element: 'itemsToEncrypt', obj: 'encryptedItems')), body
    assert body['dontEncrypt']
    assert !body['itemsToEncrypt']
    assert body['encryptedItems']
    assert body['encryptedItems']['encryptedValue']
    assert body['encryptedItems']['iv']
    assert body['encryptedItems']['encryptedKey']
    assert body['encryptedItems']['publicKeyFingerprint']
    assert body['encryptedItems']['oaepHashingAlgorithm']
  end

  def test_encrypt_nested_obj_to_encrypt
    fle = McAPI::Encryption::FieldLevelEncryption.new(@test_config)
    body = JSON.parse(JSON.generate(
                        path: {
                            to: {
                                encryptedData: {
                                    sensitive: 'secret',
                                    sensitive2: 'secret 2'
                                }
                            }
                        }
                      ))
    fle.send :encrypt_with_body, JSON.parse(JSON.generate(element: 'path.to.encryptedData', obj: 'path.to')), body
    assert body['path']
    assert body['path']['to']
    assert body['path']['to']['encryptedValue']
    assert body['path']['to']['iv']
    assert body['path']['to']['encryptedKey']
    assert body['path']['to']['publicKeyFingerprint']
    assert body['path']['to']['oaepHashingAlgorithm']
    assert !body['path']['to']['encryptedData']
  end

  def test_encrypt_nested_object_create_different_nested_object_and_delete_it
    fle = McAPI::Encryption::FieldLevelEncryption.new(@test_config)
    body = JSON.parse(JSON.generate(
                        path: {
                            to: {
                                foo: {
                                    sensitive: 'secret',
                                    sensitive2: 'secret 2'
                                }
                            }
                        }
                      ))
    fle.send :encrypt_with_body, JSON.parse(JSON.generate(element: 'path.to.foo', obj: 'path.to.encryptedFoo')), body
    assert body['path']
    assert body['path']['to']
    assert body['path']['to']['encryptedFoo']
    assert body['path']['to']['encryptedFoo']['encryptedValue']
    assert body['path']['to']['encryptedFoo']['iv']
    assert body['path']['to']['encryptedFoo']['encryptedKey']
    assert body['path']['to']['encryptedFoo']['publicKeyFingerprint']
    assert body['path']['to']['encryptedFoo']['oaepHashingAlgorithm']
    assert !body['path']['to']['foo']
  end

  def test_decrypt_nested_properties_create_new_obj
    fle = McAPI::Encryption::FieldLevelEncryption.new(@test_config)
    body = JSON.parse(JSON.generate(
                        path: {
                            to: {
                                encryptedFoo: {
                                    encryptedValue:
                                        '3097e36bf8b71637a0273abe69c23752d6157464ce49f6f35120d28bedfb63a1f2c8087be3a3bc9775592db41db87a8c',
                                    iv: '22507f596fffb45b15244356981d7ea1',
                                    encryptedKey:
                                        'd4714161898b8bc5c54a63f71ae7c7a40734e4f7c7e27d121ac5e85a3fa47946aa3546027abe0874d751d5ae701491a7f572fc30fa08dd671d358746ffe8709cba36010f97864105b175c51b6f32d36d981287698a3f6f8707aedf980cce19bfe7c5286ddba87b7f3e5abbfa88a980779037c0b7902d340d73201cf3f0b546c2ad9f54e4b71a43504da947a3cb7af54d61717624e636a90069be3c46c19b9ae8b76794321b877544dd03f0ca816288672ef361c3e8f14d4a1ee96ba72d21e3a36c020aa174635a8579b0e9af761d96437e1fa167f00888ff2532292e7a220f5bc948f8159dea2541b8c6df6463213de292b4485076241c90706efad93f9b98ea',
                                    publicKeyFingerprint:
                                        '80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279',
                                    oaepHashingAlgorithm: 'SHA512'
                                }
                            }
                        }
                      ))
    fle.send :decrypt_with_body, JSON.parse(JSON.generate(element: 'path.to.encryptedFoo', obj: 'path.to.foo')), body
    assert body['path']
    assert body['path']['to']
    assert body['path']['to']['foo']
    assert_equal body['path']['to']['foo']['accountNumber'], '5123456789012345'
    assert !body['path']['to']['encryptedFoo']
  end

  def test_decrypt_primitive_type
    fle = McAPI::Encryption::FieldLevelEncryption.new(@test_config)
    body = JSON.parse(JSON.generate(
        data: {
            encryptedValue:
                '982f5df1dfff3cc551a49091140cbb22',
            iv: '6f38f3ecd8b92c2fd2537a7235deb9a8',
            encryptedKey:
                'aebc427a2ecefc748f7f42e34a1ea6592ea20a299c107df5655483bd6ae11f9de72cb407ea0342bcac7cc29e7e9bbfbfadf8209c1f7ae2429d6f8a914d161c8a91890b3d0363b1bdd80be64712fdd6ea35496649be05e0f87001185dd79fe7a7e23c716348afe27500aaacc2cbba89793a437ae5103170fd04f0e5b4f73089c0660b44506780346e84bfb6de183f15f49132bafac651f4b4e1fadc55205d3773877c4de02c0825d7ee0b44fd3f8bb4382b999237e190352e9199eceb209fe4a91ab88fa9b4988a1a9265be38582667784da83a8ec7c307e027884d49e76771dc4a4fb472e771324f72d24299f8f621d9501d6fd59de08ccce39f533a15e17022',
            publicKeyFingerprint:
                '80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279',
            oaepHashingAlgorithm: 'SHA512'
        }
    ))
    fle.send :decrypt_with_body, JSON.parse(JSON.generate(element: 'data', obj: 'data')), body
    assert body['data']
    assert_equal body['data'], 'string'
  end
end

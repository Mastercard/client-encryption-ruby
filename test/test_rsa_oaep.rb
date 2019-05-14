# frozen_string_literal: true

require 'minitest/autorun'
require 'minitest/mock'
require_relative '../lib/mcapi/encryption/utils/openssl_rsa_oaep'
require_relative '../lib/mcapi/encryption/utils/utils'
require_relative './utils'
require 'json'

class TestRsaOAEP < Minitest::Test
  def test_add_oaep_mgf1
    res = OpenSSL::PKCS1.add_oaep_mgf1(McAPI::Utils.decode('944cec7d0a6d0299c35cbb73c47a6874', 'hex'), 256)
    assert res
  end

  def test_add_oaep_mgf1_too_large
    assert_exp_equals(OpenSSL::PKey::RSAError, 'data too large for key size') do
      OpenSSL::PKCS1.add_oaep_mgf1(McAPI::Utils.decode('944cec7d0a6d0299c35cbb73c47a6874', 'hex'), 57)
    end
  end

  def test_add_oaep_mgf1_key_size_too_small
    assert_exp_equals(OpenSSL::PKey::RSAError, 'key size too small') do
      OpenSSL::PKCS1.add_oaep_mgf1(McAPI::Utils.decode('944cec7d0a6d0299c35cbb73c47a6874', 'hex'), 40)
    end
  end

  def test_check_oaep_mgf1_error
    assert_exp_equals(OpenSSL::PKey::RSAError, 'OpenSSL::PKey::RSAError') do
      OpenSSL::PKCS1.check_oaep_mgf1(McAPI::Utils.decode('944cec7d0a6d0299c35cbb73c47a6874', 'hex'))
    end
  end

  def test_check_oaep_mgf1_error_good_zero
    assert_exp_equals(OpenSSL::PKey::RSAError, 'OpenSSL::PKey::RSAError') do
      padded = '00afff96bbebbd3c284edaf683d79641b20b593dde51e7d15b69e8f9f2cde3fb6acb96da9138187286b5f9266de7000ee5a9ec71cdff9658fbfd1d0c569cefc91f9cba28e9cee6bdd17624360191e7c7f15d4d4d72fa6c49e7bff01406b481e1cf4ca7bc8a3e4c8076dbde2e59ea4c5845a421ef4c3a8276492e6d867587f9a46b900b1a6d9617ef53710c25a1eb051dcf6994b0240121515ccd19a20c8ab7c55117060dfeec17d001d5d6fc3df1c5772c36524ca7982626fab4fb5cdc7b3c368da88637c02ab99f23f32f27cb4d16d841d91d259a636ed77c3050d6f0a16fbb224be6335e749cc0c80390ec180ae46b9d4afdedc5d68a846149778b91c88215'
      OpenSSL::PKCS1.check_oaep_mgf1(McAPI::Utils.decode(padded, 'hex'), '', OpenSSL::Digest::SHA256, OpenSSL::Digest::SHA256)
    end
  end
end

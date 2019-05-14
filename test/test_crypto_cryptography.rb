# frozen_string_literal: true

require 'minitest/autorun'
require 'minitest/mock'
require_relative '../lib/mcapi/encryption/crypto/crypto'
require 'json'

class TestCryptoCryptography < Minitest::Test
  def setup
    @test_config = JSON.parse(File.read('./test/mock/config.json'))
    @crypto = McAPI::Encryption::Crypto.new(@test_config)
  end

  def test_encrypt_valid_obj_key_and_iv
    iv = ['6f38f3ecd8b92c2fd2537a7235deb9a8'].pack('H*')
    secret_key = ['bab78b5ec588274a4dd2a60834efcf60'].pack('H*')
    assert_equal @crypto.encrypt_data(data: '{"text":"message"}', iv: iv, secret_key: secret_key)['encryptedData'], '3590b63d1520a57bd4cd1414a7a75f47d65f99e1427d6cfe744d72ee60f2b232'
  end

  def test_decrypt_valid_obj
    resp = @crypto.decrypt_data('3590b63d1520a57bd4cd1414a7a75f47d65f99e1427d6cfe744d72ee60f2b232',
                                '6f38f3ecd8b92c2fd2537a7235deb9a8',
                                'e283a661efa235fbc5e7243b7b78914a7f33574eb66cc1854829f7debfce4163f3ce86ad2c3ed2c8fe97b2258ab8a158281147698b7fddf5e82544b0b637353d2c204798f014112a5e278db0b29ad852b1417dc761593fad3f0a1771797771796dc1e8ae916adaf3f4486aa79af9d4028bc8d17399d50c80667ea73a8a5d1341a9160f9422aaeb0b4667f345ea637ac993e80a452cb8341468483b7443f764967264aaebb2cad4513e4922d076a094afebcf1c71b53ba3cfedb736fa2ca5de5c1e2aa88b781d30c27debd28c2f5d83e89107d5214e3bb3fe186412d78cefe951e384f236e55cd3a67fb13c0d6950f097453f76e7679143bd4e62d986ce9dc770')
    assert_equal resp, '{"text":"message"}'
  end

  def test_decrypt3_aes
    config = @test_config.dup
    config['encoding'] = 'hex'
    config['encryptionCertificate'] = './test/res/test_certificate.cert'
    config['privateKey'] = './test/res/test_key_pkcs1-2048.pem'
    config['oaepPaddingDigestAlgorithm'] = 'SHA-256'
    crypto = McAPI::Encryption::Crypto.new(config)
    resp = crypto.decrypt_data(
      # encrypted data
      '5ad04f6072f98dd53f06c1026339724543c8125582c120a02a193944fcb600c6411a60bc3942752fd1c2fd2176429094fae7194e6a3b5ce8e149d562d3fcab7593f5386edd556716e0c116a71894d609747d2d0b28a3ce1631329923f97f9a2d753142a74d313dfce9fa5e8add2de465302e486d6087a4da44bfaa7c2d4f3b3f0ac610842fc0f5303bf19e599c84fc7f844c80cdabf40080f74fb4f85a89b351712b36b9db0c20a22faa66e08051f1c0c0cd4e1e4a64f1773645caf4e90500d757215d91a353a3719793cdfbc2e8d52bc117ddcfa0b09bccab85d5245c0698f3613cce8fece99d2b8e5c95d5ab0f98f680ed95047e5a5b51177e8b7b775d5b8c90bd4fc0ff64e40517ab8b206ec9f71f51d13b34cd70ff1f6e32f7f8c5df4aca297ed33662879f9ba1d42cddfa1eebc8802a690b0ebba20b04a7c7ed6fcd211e6a60dd4688bfe4398c31da974819075c76895577157c67a6ede1372fab78d265a09b84923f9298592fb407260706ea5bb3f64d38e7bc7fd100833e5bdee89360510cc03980bae17d1ad3b2691111f43b4f3f61b9ed284abaa9fed4865a322390',
      # iv
      'fb2057968fa06067b6ab4c732c32cbcd',
      # key
      '7686c2472f8d53175074dd2830b4f875753343e59eec16a131f26e9e8026c3052993d8c9ad6eba04048f6a54b64160a13da28333816dfc178db2ed30068519d211c84fd7edc79838b58e97bb688b46215614308760e49d2fec95bfdf0570ce9fc5cdf814dca0dfface3d67b24b743d6003a072a882c1662ee24a9adf8b4d5825b5be74e6b73f9d08a8a2099a3fb875240ada002397c47be8a71c74e864bf8b1654365ddd2efe7b2ee44a75e08979993bfc1727cb8304607e295cab2e2dd8a8776e9678e8b9653b7e831d7b50a08d5ed1ac8c15f2933bcefef8d5b160d3a296bbdeac9d355879c0f8fc97860e17537465534095581374e9f29b1c10c7e860a638'
    )
    resp = JSON.parse(resp)
    assert !resp['mapping'].nil?
  end
end

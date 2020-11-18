# frozen_string_literal: true

require 'json'
require 'openssl'
require 'base64'
require_relative '../utils/utils'
require_relative '../utils/openssl_rsa_oaep'

module McAPI
  module Encryption
    #
    # Crypto class provide RSA/AES encrypt/decrypt methods
    #
    class Crypto
      #
      # Create a new instance with the provided config
      #
      # @param [Hash] config configuration object
      #
      def initialize(config)
        valid_config?(config)
        @encoding = config['dataEncoding']
        @cert = OpenSSL::X509::Certificate.new(IO.binread(config['encryptionCertificate']))
        if config['privateKey']
          @private_key = OpenSSL::PKey.read(IO.binread(config['privateKey']))
        elsif config['keyStore']
          @private_key = OpenSSL::PKCS12.new(IO.binread(config['keyStore']), config['keyStorePassword']).key
        end
        @oaep_hashing_alg = config['oaepPaddingDigestAlgorithm']
        @encrypted_value_field_name = config['encryptedValueFieldName']
        @encrypted_key_field_name = config['encryptedKeyFieldName']
        @public_key_fingerprint = compute_public_fingerprint(config['publicKeyFingerprintType'])
        @public_key_fingerprint_field_name = config['publicKeyFingerprintFieldName']
        @oaep_hashing_alg_field_name = config['oaepHashingAlgorithmFieldName']
      end

      #
      # Generate encryption parameters.
      #
      # @param [String] iv IV to use instead to generate a random IV
      # @param [String] secret_key Secret Key to use instead to generate a random key
      #
      # @return [Hash] hash with the generated encryption parameters
      #
      def new_encryption_params(iv = nil, secret_key = nil)
        # Generate a secret key (should be 128 (or 256) bits)
        secret_key ||= OpenSSL::Random.random_bytes(16)
        # Generate a random initialization vector (IV)
        iv ||= OpenSSL::Random.random_bytes(16)
        md = Utils.create_message_digest(@oaep_hashing_alg)
        # Encrypt secret key with issuer key
        encrypted_key = @cert.public_key.public_encrypt_oaep(secret_key, '', md, md)

        {
            iv: iv,
            secretKey: secret_key,
            encryptedKey: encrypted_key,
            oaepHashingAlgorithm: @oaep_hashing_alg,
            publicKeyFingerprint: @public_key_fingerprint,
            encoded: {
                iv: Utils.encode(iv, @encoding),
                secretKey: Utils.encode(secret_key, @encoding),
                encryptedKey: Utils.encode(encrypted_key, @encoding)
            }
        }
      end

      #
      # Perform data encryption:
      # If +iv+, +secret_key+, +encryption_params+ and +encoding+ are not provided, randoms will be generated.
      #
      # @param [String] data json string to encrypt
      # @param [String] (optional) iv Initialization vector to use to create the cipher, if not provided generate a random one
      # @param [String] (optional) encryption_params encryption parameters
      # @param [String] encoding encoding to use for the encrypted bytes (hex or base64)
      #
      # @return [String] encrypted data
      #
      def encrypt_data(data:, iv: nil, secret_key: nil, encryption_params: nil, encoding: nil)
        encoding ||= @encoding
        encryption_params ||= new_encryption_params(iv, secret_key)
        # Create Symmetric Cipher: AES 128-bit
        aes = OpenSSL::Cipher::AES.new(128, :CBC)
        # Initialize for encryption mode
        aes.encrypt
        aes.iv = encryption_params[:iv]
        aes.key = encryption_params[:secretKey]
        encrypted = aes.update(data) + aes.final
        data = {
            @encrypted_value_field_name => Utils.encode(encrypted, encoding),
            'iv' => Utils.encode(encryption_params[:iv], encoding)
        }
        data[@encrypted_key_field_name] = Utils.encode(encryption_params[:encryptedKey], encoding) if @encrypted_key_field_name
        data[@public_key_fingerprint_field_name] = @public_key_fingerprint if @public_key_fingerprint
        data[@oaep_hashing_alg_field_name] = @oaep_hashing_alg.sub('-', '') if @oaep_hashing_alg_field_name
        data
      end

      #
      # Perform data decryption
      #
      # @param [String] encrypted_data encrypted data to decrypt
      # @param [String] iv Initialization vector to use to create the Decipher
      # @param [String] encrypted_key Encrypted key to use to decrypt the data
      #                 (the key is the decrypted using the provided PrivateKey)
      #
      # @return [String] Decrypted JSON object
      #
      def decrypt_data(encrypted_data, iv, encrypted_key)
        md = Utils.create_message_digest(@oaep_hashing_alg)
        decrypted_key = @private_key.private_decrypt_oaep(Utils.decode(encrypted_key, @encoding), '', md, md)
        aes = OpenSSL::Cipher::AES.new(decrypted_key.size * 8, :CBC)
        aes.decrypt
        aes.key = decrypted_key
        aes.iv = Utils.decode(iv, @encoding)
        aes.update(Utils.decode(encrypted_data, @encoding)) + aes.final
      end

      private

      #
      # Compute the fingerprint for the provided public key
      #
      # @param [String] type: +certificate+ or +publickey+
      #
      # @return [String] the computed fingerprint encoded using the configured encoding
      #
      def compute_public_fingerprint(type)
        return unless type

        case type.downcase
        when 'certificate'
          if @encoding == 'hex'
            OpenSSL::Digest::SHA256.new(@cert.to_der).to_s
          else
            Digest::SHA256.base64digest(@cert.to_der)
          end
        when 'publickey'
          OpenSSL::Digest::SHA256.new(@cert.public_key.to_der).to_s
        else
          raise 'Selected public fingerprint not supported'
        end
      end

      #
      # Check if the passed configuration is valid
      #
      def valid_config?(config)
        props_basic = %w[oaepPaddingDigestAlgorithm paths dataEncoding encryptionCertificate encryptedValueFieldName]
        props_field = %w[ivFieldName encryptedKeyFieldName]
        props_header = %w[ivHeaderName encryptedKeyHeaderName oaepHashingAlgorithmHeaderName]
        props_fingerprint = %w[publicKeyFingerprintType publicKeyFingerprintFieldName publicKeyFingerprintHeaderName]
        props_opt_fingerprint = %w[publicKeyFingerprint]

        raise 'Config not valid: config should be an Hash.' unless config.is_a?(Hash)
        raise 'Config not valid: paths should be an array of path element.' unless config['paths'] && config['paths'].is_a?(Array)

        check_props = !Utils.contains(config, props_basic) ||
            (!Utils.contains(config, props_field) && !Utils.contains(config, props_header))
        raise 'Config not valid: please check that all the properties are defined.' if check_props

        raise 'Config not valid: paths should be not empty.' if config['paths'].length.zero?
        raise "Config not valid: dataEncoding should be 'hex' or 'base64'" if config['dataEncoding'] != 'hex' &&
            config['dataEncoding'] != 'base64'

        check_finger = !Utils.contains(config, props_opt_fingerprint) &&
            (config[props_fingerprint[1]] || config[props_fingerprint[2]]) &&
            config[props_fingerprint[0]] != 'certificate' &&
            config[props_fingerprint[0]] != 'publicKey'
        raise "Config not valid: propertiesFingerprint should be: 'certificate' or 'publicKey'" if check_finger
      end
    end
  end
end

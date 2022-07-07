# frozen_string_literal: true

require_relative 'crypto/jwe-crypto'
require_relative 'utils/hash.ext'
require 'json'

module McAPI
  module Encryption
    #
    # Performs JWE encryption on HTTP payloads.
    #
    class JweEncryption
      #
      # Create a new instance with the provided configuration
      #
      # @param [Hash] config Configuration object
      #
      def initialize(config)
        @config = config
        @crypto = McAPI::Encryption::JweCrypto.new(config)
      end

      #
      # Encrypt parts of a HTTP request using the given config
      #
      # @param [String] endpoint HTTP URL for the current call
      # @param [Object|nil] header HTTP header
      # @param [String,Hash] body HTTP body
      #
      # @return [Hash] Hash with two keys:
      # * :header header with encrypted value (if configured with header)
      # * :body encrypted body
      #
      def encrypt(endpoint, body)
        body = JSON.parse(body) if body.is_a?(String)
        config = McAPI::Utils.config?(endpoint, @config)
        body_map = body
        if config
          body_map = config['toEncrypt'].map do |v|
            encrypt_with_body(v, body)
          end
        end
        { body: config ? McAPI::Utils.compute_body(config['toEncrypt'], body_map) { body.json } : body.json }
      end

      #
      # Decrypt part of the HTTP response using the given config
      #
      # @param [Object] response object as obtained from the http client
      #
      # @return [Object] response object with decrypted fields
      #
      def decrypt(response)
        response = JSON.parse(response)
        config = McAPI::Utils.config?(response['request']['url'], @config)
        body_map = response
        if config
          body_map = config['toDecrypt'].map do |v|
            decrypt_with_body(v, response['body'])
          end
        end
        response['body'] = McAPI::Utils.compute_body(config['toDecrypt'], body_map) { response['body'] } unless config.nil?
        JSON.generate(response)
      end

      private

      def encrypt_with_body(path, body)
        elem = McAPI::Utils.elem_from_path(path['element'], body)
        return unless elem && elem[:node]

        encrypted_data = @crypto.encrypt_data(data: JSON.generate(elem[:node]))
        body = McAPI::Utils.mutate_obj_prop(path['obj'], encrypted_data, body)
        unless McAPI::Utils.json_root?(path['obj']) || path['element'] == "#{path['obj']}.#{@config['encryptedValueFieldName']}"
          McAPI::Utils.delete_node(path['element'], body)
        end
        body
      end

      def decrypt_with_body(path, body)
        elem = McAPI::Utils.elem_from_path(path['element'], body)
        return unless elem && elem[:node]

        decrypted = @crypto.decrypt_data(encrypted_data: elem[:node][@config['encryptedValueFieldName']])
        begin
          decrypted = JSON.parse(decrypted)
        rescue JSON::ParserError
          # ignored
        end

        McAPI::Utils.mutate_obj_prop(path['obj'], decrypted, body, path['element'], @encryption_response_properties)
      end
    end
  end
end

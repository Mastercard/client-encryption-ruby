# frozen_string_literal: true

require_relative 'crypto/crypto'
require_relative 'utils/hash.ext'
require_relative 'utils/utils'
require 'json'

module McAPI
  module Encryption
    #
    # Performs field level encryption on HTTP payloads.
    #
    class FieldLevelEncryption
      #
      # Create a new instance with the provided configuration
      #
      # @param [Hash] config Configuration object
      #
      def initialize(config)
        @config = config
        @crypto = McAPI::Encryption::Crypto.new(config)
        @is_with_header = config['ivHeaderName'] && config['encryptedKeyHeaderName']
        @encryption_response_properties = [@config['ivFieldName'], @config['encryptedKeyFieldName'],
                                           @config['publicKeyFingerprintFieldName'], @config['oaepHashingAlgorithmFieldName']]
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
      def encrypt(endpoint, header, body)
        body = JSON.parse(body) if body.is_a?(String)
        config = McAPI::Utils.config?(endpoint, @config)
        body_map = body
        if config
          if !@is_with_header
            body_map = config['toEncrypt'].map do |v|
              encrypt_with_body(v, body)
            end
          else
            enc_params = @crypto.new_encryption_params
            body_map = config['toEncrypt'].map do |v|
              body = encrypt_with_header(v, enc_params, header, body)
            end
          end
        end
        { header: header, body: config ? McAPI::Utils.compute_body(config['toEncrypt'], body_map) { body.json } : body.json }
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
          if !@is_with_header
            body_map = config['toDecrypt'].map do |v|
              decrypt_with_body(v, response['body'])
            end
          else
            config['toDecrypt'].each do |v|
              elem = McAPI::Utils.elem_from_path(v['obj'], response['body'])
              decrypt_with_header(v, elem, response) if elem[:node][v['element']]
            end
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

      def encrypt_with_header(path, enc_params, header, body)
        elem = McAPI::Utils.elem_from_path(path['element'], body)
        return unless elem && elem[:node]

        encrypted_data = @crypto.encrypt_data(data: JSON.generate(elem[:node]), encryption_params: enc_params)
        body = { path['obj'] => { @config['encryptedValueFieldName'] => encrypted_data[@config['encryptedValueFieldName']] } }
        set_header(header, enc_params)
        body
      end

      def decrypt_with_body(path, body)
        elem = McAPI::Utils.elem_from_path(path['element'], body)
        return unless elem && elem[:node]

        decrypted = @crypto.decrypt_data(elem[:node][@config['encryptedValueFieldName']],
                                         elem[:node][@config['ivFieldName']],
                                         elem[:node][@config['encryptedKeyFieldName']],
                                         elem[:node][@config['oaepHashingAlgorithmFieldName']])
        begin
          decrypted = JSON.parse(decrypted)
        rescue JSON::ParserError
          # ignored
        end

        McAPI::Utils.mutate_obj_prop(path['obj'], decrypted, body, path['element'], @encryption_response_properties)
      end

      def decrypt_with_header(path, elem, response)
        encrypted_data = elem[:node][path['element']][@config['encryptedValueFieldName']]
        response['body'].clear
        response['body'] = JSON.parse(@crypto.decrypt_data(encrypted_data,
                                                           response['headers'][@config['ivHeaderName']][0],
                                                           response['headers'][@config['encryptedKeyHeaderName']][0],
                                                           response['headers'][@config['oaepHashingAlgorithmHeaderName']][0]))
      end

      def set_header(header, params)
        header[@config['encryptedKeyHeaderName']] = params[:encoded][:encryptedKey]
        header[@config['ivHeaderName']] = params[:encoded][:iv]
        header[@config['oaepHashingAlgorithmHeaderName']] = params[:oaepHashingAlgorithm].sub('-', '')
        header[@config['publicKeyFingerprintHeaderName']] = params[:publicKeyFingerprint]
      end
    end
  end
end

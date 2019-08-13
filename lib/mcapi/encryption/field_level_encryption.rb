# frozen_string_literal: true

require_relative 'crypto/crypto'
require_relative 'utils/hash.ext'
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
      # @param [Object] config Configuration object
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
      # @param [Object] header HTTP header
      # @param [String,Hash] body HTTP body
      #
      # @return [Hash] Hash with two keys:
      # * :header header with encrypted value (if configured with header)
      # * :body encrypted body
      #
      def encrypt(endpoint, header, body)
        body = JSON.parse(body) if body.is_a?(String)
        config = config?(endpoint)
        if config
          if !@is_with_header
            config['toEncrypt'].each do |v|
              encrypt_with_body(v, body)
            end
          else
            enc_params = @crypto.new_encryption_params
            config['toEncrypt'].each do |v|
              body = encrypt_with_header(v, enc_params, header, body)
            end
          end
        end
        { header: header, body: body.json }
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
        config = config?(response['request']['url'])
        if config
          if !@is_with_header
            config['toDecrypt'].each do |v|
              decrypt_with_body(v, response['body'])
            end
          else
            config['toDecrypt'].each do |v|
              elem = elem_from_path(v['obj'], response['body'])
              decrypt_with_header(v, elem, response) if elem[:node][v['element']]
            end
          end
        end
        JSON.generate(response)
      end

      private

      def encrypt_with_body(path, body)
        elem = elem_from_path(path['element'], body)
        return unless elem && elem[:node]
        encrypted_data = @crypto.encrypt_data(data: JSON.generate(elem[:node]))
        McAPI::Utils.mutate_obj_prop(path['obj'], encrypted_data, body)
        McAPI::Utils.delete_node(path['element'], body) if path['element'] != "#{path['obj']}.#{@config['encryptedValueFieldName']}"
      end

      def encrypt_with_header(path, enc_params, header, body)
        elem = elem_from_path(path['element'], body)
        return unless elem && elem[:node]
        encrypted_data = @crypto.encrypt_data(data: JSON.generate(elem[:node]), encryption_params: enc_params)
        body = { path['obj'] => { @config['encryptedValueFieldName'] => encrypted_data[@config['encryptedValueFieldName']] } }
        set_header(header, enc_params)
        body
      end

      def decrypt_with_body(path, body)
        elem = elem_from_path(path['element'], body)
        return unless elem && elem[:node]
        decrypted = @crypto.decrypt_data(elem[:node][@config['encryptedValueFieldName']],
                                 elem[:node][@config['ivFieldName']],
                                 elem[:node][@config['encryptedKeyFieldName']])
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
                                                           response['headers'][@config['encryptedKeyHeaderName']][0]))
      end

      def elem_from_path(path, obj)
        parent = nil
        paths = path.split('.')
        if path && !paths.empty?
          paths.each do |e|
            parent = obj
            obj = obj[e]
          end
        end
        { node: obj, parent: parent }
      rescue StandardError
        nil
      end

      def config?(endpoint)
        return unless endpoint

        endpoint = endpoint.split('?').shift
        conf = @config['paths'].select { |e| endpoint.match(e['path']) }
        conf.empty? ? nil : conf[0]
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

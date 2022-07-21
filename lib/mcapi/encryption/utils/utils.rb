# frozen_string_literal: true

require 'base64'

module McAPI
  #
  # Utils module
  module Utils
    #
    # Data encoding
    #
    def self.encode(data, encoding)
      return unless encoding

      case encoding.downcase
      when 'hex'
        data.each_byte.map { |b| format('%02x', b.to_i) }.join
      when 'base64'
        Base64.encode64(data).delete("\n")
      else
        raise 'Encoding not supported'
      end
    end

    #
    # Data decoding
    #
    def self.decode(data, encoding)
      return unless encoding

      case encoding.downcase
      when 'hex'
        [data].pack('H*')
      when 'base64'
        Base64.decode64(data)
      else
        raise 'Encoding not supported'
      end
    end

    #
    # Create Digest object for the provided digest string
    #
    def self.create_message_digest(digest)
      return unless digest

      case digest.upcase
      when 'SHA-256', 'SHA256'
        OpenSSL::Digest::SHA256
      when 'SHA-512', 'SHA512'
        OpenSSL::Digest::SHA512
      else
        raise 'Digest algorithm not supported'
      end
    end

    def self.contains(config, props)
      props.any? do |i|
        config.key? i
      end
    end

    #
    # Perform JSON object properties manipulations
    #
    def self.mutate_obj_prop(path, value, obj, src_path = nil, properties = [])
      tmp = obj
      prev = nil
      return obj unless path

      delete_node(src_path, obj, properties) if src_path
      paths = path.split('.')
      unless path == '$'
        paths.each do |e|
          tmp[e] = {} unless tmp[e]
          prev = tmp
          tmp = tmp[e]
        end
      end
      elem = path.split('.').pop
      if elem == '$'
        obj = value # replace root
      elsif value.is_a?(Hash) && !value.is_a?(Array)
        prev[elem] = {} unless prev[elem].is_a?(Hash)
        override_props(prev[elem], value)
      else
        prev[elem] = value
      end
      obj
    end

    def self.override_props(target, obj)
      obj.each do |k, _|
        target[k] = obj[k]
      end
    end

    #
    # Delete node from JSON object
    #
    def self.delete_node(path, obj, properties = [])
      return unless path && obj

      paths = path.split('.')
      to_delete = paths[paths.size - 1]
      paths.each_with_index do |e, index|
        prev = obj
        next unless obj[e]

        obj = obj[e]
        prev.delete(to_delete) if obj && index == paths.size - 1
      end
      obj.keys.each { |e| obj.delete(e) } if paths.length == 1 && paths[0] == '$'
      properties.each { |e| obj.delete(e) } if paths.empty?
    end

    #
    # Parse raw HTTP Header
    #
    def self.parse_header(raw)
      raw = raw.partition("\n").last
      header = Hash.new([].freeze)
      field = nil
      raw.each_line do |line|
        case line
        when /^([A-Za-z0-9!\#$%&'*+\-.^_`|~]+):\s*(.*?)\s*\z/om
          field = Regexp.last_match(1)
          value = Regexp.last_match(2)
          field.downcase!
          header[field] = [] unless header.key?(field)
          header[field] << value
        when /^\s+(.*?)\s*\z/om
          value = Regexp.last_match(1)
          raise Exception, "bad header '#{line}'." unless field

          header[field][-1] << ' ' << value
        else
          raise Exception, "bad header '#{line}'."
        end
      end
      header.each do |_key, values|
        values.each do |value|
          value.strip!
          value.gsub!(/\s+/, ' ')
        end
      end
      header
    end

    #
    # Get an element from the JSON path
    #
    def self.elem_from_path(path, obj)
      parent = nil
      paths = path.split('.')
      if path && !paths.empty?
        paths.each do |e|
          parent = obj
          obj = json_root?(e) ? obj : obj[e]
        end
      end
      { node: obj, parent: parent }
    rescue StandardError
      nil
    end

    #
    # Check whether the encryption/decryption path refers to the root element
    #
    def self.json_root?(elem)
      elem == '$'
    end

    def self.config?(endpoint, config)
      return unless endpoint

      endpoint = endpoint.split('?').shift
      conf = config['paths'].select { |e| endpoint.match(e['path']) }
      conf.empty? ? nil : conf[0]
    end

    def self.compute_body(config_param, body_map)
      encryption_param?(config_param, body_map) ? body_map[0] : yield
    end

    def self.encryption_param?(enc_param, body_map)
      enc_param.length == 1 && body_map.length == 1
    end

    def self.parse_decrypted_payload(payload)
      parsed_payload =  payload.gsub("\\u000f", "")
      parsed_payload = parsed_payload.gsub("\\", "")
      if parsed_payload[0] == "\""
        parsed_payload = parsed_payload.delete_prefix('"').delete_suffix('"')
      end
      parsed_payload
    end
  end
end

# frozen_string_literal: true

require 'minitest/autorun'
require 'minitest/mock'

require_relative '../lib/mcapi/encryption/openapi_interceptor'

class TestInterceptor < Minitest::Test
  HEADER = JSON.parse('{"Accept":"application/json","Content-Type":"application/json"}')
  BODY = JSON.parse('{"mapping":{"customer_identifier":"CUST_12345","merchant":{"name":"LAWN MOWER SERVICE","mastercard_assigned_id":"354315","merchant_category_code":"4563"}}}')

  RAW_HEADER = 'HTTP/1.1 200 OK
x-oaep-hashing-algorithm: SHA256
x-encrypted-key: z9hICyBnN+X857KoYn1Ft3GOmMt+GGBcNvI+QlRmKZ2DVJgfaA9YoB96tE9SNRMux+9ZbAEARGXsnURFrcG3+xDf0XUvzwmcXqC5tZw4Xrw8LNXjZBPnHGCe7S1MY+x90BBK+pxD+LEkCIlsHYugButd8SgHehb34FQ35lJA/RuMQoQgbbqBAVdPNoFLap8HkzIMk83Kfuqe7vlZtEinFALs78JTDIah2Ytybwq83a+NXstKj8o8PvyKZEmD5QgrMnuxozSsWZso/OdS6Po5WFxpPaEIvOtsPw79SvujPlE2v1WK7yAvwNbBRvuxtXdz4mWNUNsmvpxD+Cvw1/2AQA==
RequestId: 1c1059e2-2b91-4a08-a8f9-dfb65908242e
x-iv: 4+vu1fcirK916IukdAfn7A==
x-public-key-fingerprint: 761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79
Content-Type: application/json

'

  class Request
    attr_accessor :base_url
  end

  class Response
    attr_reader :body
    attr_reader :request
    attr_accessor :options

    def initialize(req, body)
      @request = Request.new
      @request.base_url = req
      @body = body
      @options = {}
    end
  end

  class Config
    attr_accessor :base_url
  end

  class MockApiClient
    def initialize(config = nil)
      @config = config
    end

    attr_reader :config

    def call_api(_http_method, _path, opts)
      opts
    end

    def deserialize(response, _return_type)
      response
    end
  end

  def setup
    @config = JSON.parse(File.read('./test/mock/config-interceptor.json'))
  end

  def test_intercept_request_nil_opts
    api_client = MockApiClient.new
    McAPI::Encryption::OpenAPIInterceptor.install_field_level_encryption(api_client, @config)
    resp = api_client.call_api('GET', '/resource', nil)
    assert_nil(resp)
  end

  def test_intercept_request_with_opts
    api_client = MockApiClient.new
    McAPI::Encryption::OpenAPIInterceptor.install_field_level_encryption(api_client, @config)
    opts = {}
    opts[:body] = BODY
    opts[:header_params] = HEADER
    resp = api_client.call_api('GET', '/mappings/mappingId', opts)
    assert resp[:body]
    assert !JSON.parse(resp[:body])['encrypted_payload']['data'].empty?
  end

  def test_intercept_response_nil
    api_client = MockApiClient.new
    McAPI::Encryption::OpenAPIInterceptor.install_field_level_encryption(api_client, @config)
    assert_nil api_client.deserialize(nil, nil)
  end

  def test_intercept_response
    config = Config.new
    config.base_url = 'https://api.mastercard.com/example_api'
    api_client = MockApiClient.new(config)
    McAPI::Encryption::OpenAPIInterceptor.install_field_level_encryption(api_client, @config)
    response_body = JSON.generate(JSON.parse(File.read('./test/mock/response-interceptor.json')))
    response = Response.new('https://api.mastercard.com/example_api/mappings/search', response_body)
    response.options[:response_headers] = RAW_HEADER
    decrypted = api_client.deserialize(response, Response)
    assert decrypted
    assert decrypted.options
    assert decrypted.options[:response_body]
    decrypted = JSON.parse(decrypted.options[:response_body])
    assert_equal decrypted['mapping']['merchant']['name'], 'LAWN MOWER SERVICE'
  end
end

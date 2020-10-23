# client-encryption-ruby

[![](https://travis-ci.org/Mastercard/client-encryption-ruby.svg?branch=master)](https://travis-ci.org/Mastercard/client-encryption-ruby)
[![](https://sonarcloud.io/api/project_badges/measure?project=Mastercard_client-encryption-ruby&metric=alert_status)](https://sonarcloud.io/dashboard?id=Mastercard_client-encryption-ruby)
[![](https://sonarcloud.io/api/project_badges/measure?project=Mastercard_client-encryption-ruby&metric=coverage)](https://sonarcloud.io/dashboard?id=Mastercard_client-encryption-ruby)
[![](https://sonarcloud.io/api/project_badges/measure?project=Mastercard_client-encryption-ruby&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=Mastercard_client-encryption-ruby)
[![](https://github.com/Mastercard/oauth1-signer-ruby/workflows/broken%20links%3F/badge.svg)](https://github.com/Mastercard/oauth1-signer-ruby/actions?query=workflow%3A%22broken+links%3F%22)
[![](https://img.shields.io/gem/v/mastercard-client-encryption.svg)](https://rubygems.org/gems/mastercard-client-encryption)
[![](https://img.shields.io/badge/license-MIT-yellow.svg)](https://github.com/Mastercard/client-encryption-ruby/blob/master/LICENSE)

## Table of Contents

- [Overview](#overview)
  - [Compatibility](#compatibility)
  - [References](#references)
- [Usage](#usage)
  - [Prerequisites](#prerequisites)
  - [Adding the Library to Your Project](#adding-the-libraries-to-your-project)
  - [Performing Field Level Encryption and Decryption](#performing-field-level-encryption-and-decryption)
  - [Integrating with OpenAPI Generator API Client Libraries](#integrating-with-openapi-generator-api-client-libraries)

## Overview <a name="overview"></a>

Ruby library for Mastercard API compliant payload encryption/decryption.

### Compatibility <a name="compatibility"></a>

- Ruby 2.4.4+
- Truffle Ruby 1.0.0+

### References <a name="references"></a>

<img src="https://user-images.githubusercontent.com/3964455/55345820-c520a280-54a8-11e9-8235-407199fa1d97.png" alt="Encryption of sensitive data" width="75%" height="75%"/>

## Usage <a name="usage"></a>

### Prerequisites <a name="prerequisites"></a>

Before using this library, you will need to set up a project in the [Mastercard Developers Portal](https://developer.mastercard.com). 

As part of this set up, you'll receive:

- A public request encryption certificate (aka _Client Encryption Keys_)
- A private response decryption key (aka _Mastercard Encryption Keys_)

### Installation <a name="adding-the-libraries-to-your-project"></a>

If you want to use **mastercard-client-encryption** with [Ruby](https://www.ruby-lang.org/en/), it is available as Gem:

- [https://rubygems.org/gems/mastercard-client-encryption](https://rubygems.org/gems/mastercard-client-encryption)

**Adding the library to your project**

Add this line to your application's Gemfile:

```ruby
gem 'mastercard-client-encryption'
```

And then execute:

```bash
$ bundle
```

Or install it yourself as:

```bash
$ gem install mastercard-client-encryption
```

Import the library:

```ruby
require 'mcapi/encryption/openapi_interceptor' # to add the interceptor
# or
require 'mcapi/encryption/field_level_encryption' # to perform ad-hoc encryption/decryption
```



### Performing Field Level Encryption and Decryption <a name="performing-field-level-encryption-and-decryption"></a>

- [Introduction](#introduction)
- [Configuring the Field Level Encryption](#configuring-the-field-level-encryption)
- [Performing Encryption](#performing-encryption)
- [Performing Decryption](#performing-decryption)

#### Introduction <a name="introduction"></a>

The core methods responsible for payload encryption and decryption are `encrypt` and `decrypt` in the `FieldLevelEncryption` class.

- `encrypt()` usage:

```ruby
fle = McAPI::Encryption::FieldLevelEncryption.new(@config)
encrypted_request_payload = fle.encrypt(endpoint, header, body)
```

- `decrypt()` usage:

```ruby
fle = McAPI::Encryption::FieldLevelEncryption.new(@config)
decrypted_response_payload = fle.decrypt(encrypted_response_payload)
```

#### Configuring the Field Level Encryption <a name="configuring-the-field-level-encryption"></a>

`FieldLevelEncryption` needs a config object to instruct how to decrypt/decrypt the payloads. Example:

```json
{
  "paths": [
    {
      "path": "/resource",
      "toEncrypt": [
        {
          "element": "path.to.foo",
          "obj": "path.to.encryptedFoo"
        }
      ],
      "toDecrypt": [
        {
          "element": "path.to.encryptedFoo",
          "obj": "path.to.foo"
        }
      ]
    }
  ],
  "ivFieldName": "iv",
  "encryptedKeyFieldName": "encryptedKey",
  "encryptedValueFieldName": "encryptedData",
  "dataEncoding": "hex",
  "encryptionCertificate": "./path/to/public.cert",
  "privateKey": "./path/to/your/private.key",
  "oaepPaddingDigestAlgorithm": "SHA-256"
}
```

For all config options, please see:

- [Configuration object](https://github.com/Mastercard/client-encryption-ruby/wiki/Configuration-Object) for all config options

We have a predefined set of configurations to use with Mastercard services:

- [Service configurations](https://github.com/Mastercard/client-encryption-ruby/wiki/Service-Configurations-for-Client-Encryption-Ruby)



#### Performing Encryption <a name="performing-encryption"></a>

Call `FieldLevelEncryption.encrypt()` with a JSON request payload, and optional `header` object.

Example using the configuration [above](#configuring-the-field-level-encryption):

```ruby
payload = JSON.generate({
  path: {
    to: {
      foo: {
        sensitiveField1: 'sensitiveValue1',
        sensitiveField2: 'sensitiveValue2'
      }
    }
  }
})
fle = McAPI::Encryption::FieldLevelEncryption.new(@config)
request_payload = fle.encrypt("/resource", header, payload)
```

Output:

```json
{
    "path": {
        "to": {
            "encryptedFoo": {
                "iv": "7f1105fb0c684864a189fb3709ce3d28",
                "encryptedKey": "67f467d1b653d98411a0c6d3c(...)ffd4c09dd42f713a51bff2b48f937c8",
                "encryptedData": "b73aabd267517fc09ed72455c2(...)dffb5fa04bf6e6ce9ade1ff514ed6141",
                "publicKeyFingerprint": "80810fc13a8319fcf0e2e(...)82cc3ce671176343cfe8160c2279",
                "oaepHashingAlgorithm": "SHA256"
            }
        }
    }
}
```

#### Performing Decryption <a name="performing-decryption"></a>

Call `FieldLevelEncryption.decrypt()` with an (encrypted) `response` object with the following fields:

- `body`: json payload
- `request.url`: requesting url
- `header`: *optional*, header object

Example using the configuration [above](#configuring-the-field-level-encryption):

```ruby
response = {}
response[:request] = { url: '/resource1' }
response[:body] = 
{
  path: {
    to: {
      encryptedFoo: {
        iv: 'e5d313c056c411170bf07ac82ede78c9',
        encryptedKey: 'e3a56746c0f9109d18b3a2652b76(...)f16d8afeff36b2479652f5c24ae7bd',
        encryptedData: '809a09d78257af5379df0c454dcdf(...)353ed59fe72fd4a7735c69da4080e74f',
        oaepHashingAlgorithm: 'SHA256',
        publicKeyFingerprint: '80810fc13a8319fcf0e2e(...)3ce671176343cfe8160c2279'
      }
    }
  }
}
fle = McAPI::Encryption::FieldLevelEncryption.new(@config)
response_payload = fle.decrypt(response)
```

Output:

```json
{
  "path": {
    "to": {
      "foo": {
        "sensitiveField1": "sensitiveValue1",
        "sensitiveField2": "sensitiveValue2"
      }
    }
  }
}
```

### Integrating with OpenAPI Generator API Client Libraries <a name="integrating-with-openapi-generator-api-client-libraries"></a>

[OpenAPI Generator](https://github.com/OpenAPITools/openapi-generator) generates API client libraries from [OpenAPI Specs](https://github.com/OAI/OpenAPI-Specification). 
It provides generators and library templates for supporting multiple languages and frameworks.

The **client-encryption-ruby** library provides a method you can use to integrate the OpenAPI generated client with this library:
```ruby
McAPI::Encryption::OpenAPIInterceptor.install_field_level_encryption(open_api_client, config)
```
This method will add the field level encryption in the generated OpenApi client, taking care of encrypting request and decrypting response payloads, but also of updating HTTP headers when needed, automatically, without manually calling `encrypt()`/`decrypt()` functions for each API request or response.

##### OpenAPI Generator <a name="openapi-generator"></a>

OpenAPI client can be generated, starting from your OpenAPI Spec / Swagger using the following command:

```shell
java -jar openapi-generator-cli.jar generate -i openapi-spec.yaml -l ruby -o out
```

Client library will be generated in the `out` folder.

See also: 

- [OpenAPI Generator (executable)](https://mvnrepository.com/artifact/org.openapitools/openapi-generator-cli)

##### Usage of the `McAPI::Encryption::OpenAPIInterceptor.install_field_level_encryption`:

To use it:

1. Generate the OpenAPI client, as [above](#openapi-generator)

2. Import the **mastercard-client-encryption** OpenAPI Interceptor and the generated OpenApi client

   ```ruby
   require 'mcapi/encryption/openapi_interceptor'
   require_relative './out/generated_open_apiclient' #import generated OpenAPI client
   ```

3. Install the field level encryption in the generated client:

   ```ruby
   # Read the service configuration obj
   @config = File.read('./config.json')   
   # Create a new instance of the generated client
   @api_client = client::ApiClient.new
   # Enable field level encryption
   McAPI::Encryption::OpenAPIInterceptor.install_field_level_encryption(@api_client, @config)
   ```

4. Use the `api_client` object with the Field Level Encryption enabled:

   Example:

   ```ruby
   api_instance = OpenApiService::ServiceApi.new @api_client
   body = # ... #
   response = api_instance.create_merchants(body)
   # requests and responses will be automatically encrypted and decrypted
   # accordingly with the configuration object used
   
   # ... use the (decrypted) response object here ... 
   ```


# frozen_string_literal: true

require 'minitest/autorun'
require 'minitest/mock'
require_relative '../lib/mcapi/encryption/utils/utils'
require_relative './utils'
require 'json'

class TestUtils < Minitest::Test
  def test_decode_wrong_encoding
    assert_equal(assert_raises(RuntimeError) do
      McAPI::Utils.decode('dGVzdGluZ3V0aWxz', 'XXX')
    end.message, 'Encoding not supported')
  end

  def test_decode_from_hex
    assert_equal 'testingutils', McAPI::Utils.decode('74657374696E677574696C73', 'hex')
  end

  def test_decode_from_base64
    assert_equal 'testingutils', McAPI::Utils.decode('dGVzdGluZ3V0aWxz', 'base64')
  end

  def test_encoding_decoding_hex
    str = 'testing utils'
    res = McAPI::Utils.encode(str, 'hex')
    assert_equal str, McAPI::Utils.decode(res, 'hex')
  end

  def test_encoding_decoding_base64
    str = 'testing utils'
    res = McAPI::Utils.encode(str, 'base64')
    assert_equal str, McAPI::Utils.decode(res, 'base64')
  end

  def test_encode_nil
    res = McAPI::Utils.encode('data', nil)
    assert_nil(res)
  end

  def test_encode_not_supported
    assert_exp_equals(RuntimeError, 'Encoding not supported') do
      McAPI::Utils.encode('data', 'someencoding')
    end
  end

  def test_decode_nil
    res = McAPI::Utils.decode('data', nil)
    assert_nil(res)
  end

  def test_decode_not_supported
    assert_exp_equals(RuntimeError, 'Encoding not supported') do
      McAPI::Utils.decode('data', 'some encoding')
    end
  end

  def test_create_message_digest_not_supported
    assert_exp_equals(RuntimeError, 'Digest algorithm not supported') do
      McAPI::Utils.create_message_digest('some digest')
    end
  end

  def test_mutate_obj_prop_change_obj_value
    obj = {
        first: {
            second: {
                third: {
                    field: 'value'
                }
            }
        }
    }
    path = 'first.second.third'
    obj = JSON.parse(JSON.generate(obj))
    McAPI::Utils.mutate_obj_prop(path, 'changed', obj)
    assert_equal 'changed', obj['first']['second']['third']
  end

  def test_mutate_obj_prop_dont_change
    obj = {
        first: {
            second: {
                third: {
                    field: 'value'
                }
            }
        }
    }
    path = 'first.second.not_exists'
    obj = JSON.parse(JSON.generate(obj))
    McAPI::Utils.mutate_obj_prop(path, 'changed', obj)
    assert_equal 'value', obj['first']['second']['third']['field']
  end

  def test_mutate_obj_prop_field_not_found
    obj = {
        first: {
            second: {
                third: {
                    field: 'value'
                }
            }
        }
    }
    path = 'first.foo.third'
    obj = JSON.parse(JSON.generate(obj))
    McAPI::Utils.mutate_obj_prop(path, 'changed', obj)
    assert_equal 'value', obj['first']['second']['third']['field']
  end

  def test_mutate_obj_prop_field_not_found_create_it_long_path
    obj = {
        first: {
            second: {
                third: {
                    field: 'value'
                }
            }
        }
    }
    path = 'foo.bar.yet.another.foo.bar'
    obj = JSON.parse(JSON.generate(obj))
    McAPI::Utils.mutate_obj_prop(path, 'changed', obj)
    obj = JSON.generate(obj)
    res = JSON.generate(
      "first": {
          "second": {
              "third": {
                  "field": 'value'
              }
          }
      },
      "foo": {
          "bar": {
              "yet": {
                  "another": {
                      "foo": {
                          "bar": 'changed'
                      }
                  }
              }
          }
      }
    )
    assert_equal obj, res
  end

  def test_mutate_obj_prop_first_part_correct_field_not_found_create_it
    obj = {
        first: {
            second: {
                third: {
                    field: 'value'
                }
            }
        }
    }
    path = 'first.foo.third'
    obj = JSON.parse(JSON.generate(obj))
    McAPI::Utils.mutate_obj_prop(path, 'changed', obj)
    obj = JSON.generate(obj)
    res = JSON.generate(
      first: {
          second: {
              third: {
                  field: 'value'
              }
          },
          foo: {
              third: 'changed'
          }
      }
    )
    assert_equal obj, res
  end

  def test_parse_header_empty
    res = McAPI::Utils.parse_header('')
    assert_equal res, {}
  end

  def test_parse_header_wrong_format
    assert_exp_equals(Exception, 'bad header \'efgc\'.') do
      McAPI::Utils.parse_header("abcd\nefgc")
    end
  end

  def test_parse_header_one_line
    res = McAPI::Utils.parse_header('First Line')
    assert_equal res, {}
  end

  def test_parse_header_more_lines
    res = McAPI::Utils.parse_header("First Line\nx-one: one")
    assert_equal res, 'x-one' => ['one']
  end

  def test_parse_header_more_lines_2
    res = McAPI::Utils.parse_header("First Line\nx-one: one\nx-two: two")
    assert_equal res, 'x-one' => ['one'], 'x-two' => ['two']
  end

  def test_parse_header_with_spaces
    res = McAPI::Utils.parse_header("First Line\nx-one: one\n           \n")
    assert_equal res, 'x-one' => ['one']
  end

  def test_parse_header_bad_header
    assert_exp_equals(Exception, "bad header '       \n'.") do
      McAPI::Utils.parse_header("First Line\n       \n")
    end
  end

  def test_delete_node_nulls
    McAPI::Utils.delete_node(nil, nil, nil)
    McAPI::Utils.delete_node('path.to.foo', nil, nil)
    body = JSON.parse(JSON.generate({}))
    McAPI::Utils.delete_node('path.to.foo', body)
    assert_equal body, JSON.parse(JSON.generate({}))
  end

  def test_delete_not_found_path_shouldn_t_remove
    body = JSON.parse(JSON.generate(path: { to: { foo: { field: 'value' } } }))
    body_dup = body.dup
    McAPI::Utils.delete_node('path.to.notfound', body)
    assert_equal body, body_dup
  end

  def test_delete_found_path_should_remove
    body = JSON.parse(JSON.generate(path: { to: { foo: { field: 'value' } } }))
    McAPI::Utils.delete_node('path.to.foo', body)
    assert_equal body, JSON.parse(JSON.generate(path: { to: {} }))
  end

  def test_delete_root_path_without_properties_shouldn_t_remove
    body_hash = { path: { to: { foo: { field: 'value' } } } }
    body = JSON.parse(JSON.generate(body_hash))
    McAPI::Utils.delete_node('', body)
    assert_equal body, JSON.parse(JSON.generate(body_hash))
  end

  def test_delete_root_path_with_properties_should_remove_the_properties
    body_hash = { path: { to: { foo: { field: 'value' } } }, prop: 'prop', prop2: 'prop2' }
    body = JSON.parse(JSON.generate(body_hash))
    McAPI::Utils.delete_node('', body, %w[prop prop2])
    assert_equal body, JSON.parse(JSON.generate("path": { "to": { "foo": { "field": 'value' } } }))
  end
end

# frozen_string_literal: true

require 'minitest/autorun'
require 'minitest/mock'

def assert_exp_equals(exp, msg = '')
  if block_given?
    assert_equal(assert_raises(exp) do
      yield
    end.message, msg)
  end
end

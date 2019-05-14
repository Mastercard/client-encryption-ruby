# frozen_string_literal: true

#
# Hash extension
#
class Hash
  #
  # Parse the current hash as json
  #
  def json
    JSON.parse(to_json)
  end
end

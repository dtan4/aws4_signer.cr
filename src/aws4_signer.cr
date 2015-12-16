require "./aws4_signer/*"

class Aws4Signer
  def initialize(access_key_id, secret_access_key, region, service, options = {} of Symbol => String?)
    @access_key_id = access_key_id
    @secret_access_key = secret_access_key
    @region = region
    @service = service
    @options = options
  end

  def sign(verb, uri, headers, body) : Signature
    raise "URI must be provided" unless uri
    Signature.new(@access_key_id, @secret_access_key, @region, @service, uri, verb, headers, body, @options)
  end

  def sign_headers(verb, uri, headers = HTTP::Request.new, body = "") : HTTP::Headers
    sign(verb, uri, headers, body).generate_signed_headers
  end
end

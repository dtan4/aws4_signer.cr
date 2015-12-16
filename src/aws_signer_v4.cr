require "./aws_signer_v4/*"

class AwsSignerV4
  def initialize(access_key_id, secret_access_key, region, service, options)
    @access_key_id = access_key_id
    @secret_access_key = secret_access_key
    @region = region
    @service = service
    @options = options
  end

  def sign(verb, uri, headers, body)
    raise "URI must be provided" unless uri
    Signature.new(@access_key_id, @secret_access_key, @region, @service, uri, verb, headers, body, @options)
  end

  def sign_http_request(verb, uri, headers, body)
    sign(verb, uri, headers, body).generate_signed_headers
  end
end

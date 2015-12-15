class AwsSignerV4
  class Signature
    def initialize(access_key_id, secret_access_key, region, service, uri, verb, headers, body, options)
      @access_key_id = access_key_id
      @secret_access_key = secret_access_key
      @region = region
      @service = service
      @uri = uri
      @verb = verb
      @headers = headers
      @body = body
      @options = options

      @headers["x-amz-date"] ||= @headers.delete("X-Amz-Date")
      @headers["x-amz-date"] = Time.utc_now.to_s("%Y%m%dT%H%M%SZ") unless @headers["x-amz-date"]
    end

    getter :region, :service, :verb, :uri, :headers, :body, :access_key_id, :secret_access_key
  end
end

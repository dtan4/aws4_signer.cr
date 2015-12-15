class AwsSignerV4
  class Signature
    X_AMZ_DATE_FORMAT = "%Y%m%dT%H%M%SZ"

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

      unless @headers["x-amz-date"]
        # TODO(dtan4): Does it really need to assign date_now?
        date_now = Time.utc_now
        @date = date_now
        @headers["x-amz-date"] = date_now.to_s(X_AMZ_DATE_FORMAT)
      end
    end

    getter :region, :service, :verb, :uri, :headers, :body, :access_key_id, :secret_access_key

    def date
      # TODO(dtan4): Does it really need to call #to_s?
      @date = Time.parse(@headers["x-amz-date"].to_s, X_AMZ_DATE_FORMAT, Time::Kind::Utc) unless @date
      @date
    end
  end
end

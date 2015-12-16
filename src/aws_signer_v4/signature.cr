require "openssl"
require "openssl/digest"
require "openssl/hmac"

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

      @headers["Host"] ||= @headers.delete("host") || uri.host
      @headers["x-amz-security-token"] = options[:security_token] if options.has_key?(:security_token) && options[:security_token]
    end

    getter :region, :service, :verb, :uri, :headers, :body, :access_key_id, :secret_access_key

    def authorization_header
      "AWS4-HMAC-SHA256 " \
        "Credential=#{@access_key_id}/#{scope}," \
        "SignedHeaders=#{signed_headers}," \
        "Signature=#{signature}"
    end

    def canonical_headers
      return @canonical_headers if @canonical_headers

      signed = [] of String

      hash = @headers.to_a.sort_by { |header| header[0].downcase }.map do |header|
        name, value = header[0], header[1]

        next if name == "Authorization"

        signed << name.downcase

        if value.is_a?(Array)
          value.map { |v| "#{name.downcase}:#{v.to_s.strip}\n" }
        else
          "#{name.downcase}:#{value.to_s.strip}\n"
        end
      end.compact.join

      @signed_headers = signed.join(";")
      @canonical_headers = hash
      hash
    end

    def canonical_request
      @canonical_request ||= [
        @verb.upcase,
        @uri.path,
        @uri.query,
        canonical_headers,
        signed_headers,
        hashed_payload,
      ].join("\n")
    end

    def date
      # TODO(dtan4): Does it really need to call #to_s?
      @date ||= Time.parse(@headers["x-amz-date"].to_s, X_AMZ_DATE_FORMAT, Time::Kind::Utc)
    end

    def date_key
      @date_key ||= hmac("AWS4#{@secret_access_key}", date.to_s("%Y%m%d"))
    end

    def date_region_key
      @date_region_key ||= hmac(date_key, @region)
    end

    def date_region_service_key
      @date_region_service_key ||= hmac(date_region_key, @service)
    end

    def hashed_payload
      @hashed_payload ||= sha256_digest(body)
    end

    def scope
      "#{date.to_s("%Y%m%d")}/#{@region}/#{@service}/aws4_request"
    end

    def sha256_digest(data)
      digest = OpenSSL::Digest.new("SHA256")
      digest << data
      digest.hexdigest
    end

    def signature
      @signature ||= hmac(signing_key, string_to_sign, :hex)
    end

    def signed_headers
      canonical_headers
      @signed_headers
    end

    def signing_key
      @signing_key ||= hmac(date_region_service_key, "aws4_request")
    end

    def string_to_sign
      @string_to_sign = [
        "AWS4-HMAC-SHA256",
        @headers["x-amz-date"],
        scope,
        sha256_digest(canonical_request),
      ].join("\n")
    end

    private def hmac(key, data, hex = false)
      hex ? OpenSSL::HMAC.hexdigest(:sha256, key, data) : OpenSSL::HMAC.digest(:sha256, key, data)
    end
  end
end

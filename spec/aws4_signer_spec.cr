require "./spec_helper"

require "http/headers"

describe Aws4Signer do
  let(:signer) { Aws4Signer.new("AKID", "SECRET", "xx-region-1", "svc", {} of Symbol => String?) }
  let(:headers) do
    h = HTTP::Headers.new
    h["foo"] = "bar"
    h
  end

  describe "sign" do
    let(:uri) { URI.parse("https://example.org/foo/bar?baz=blah") }

    it "should return Signature" do
      signature = signer.sign("PUT", uri, headers, "hello")

      assert signature.is_a?(Aws4Signer::Signature)
      assert_equal "AKID", signature.access_key_id
      assert_equal "SECRET", signature.secret_access_key
      assert_equal "xx-region-1", signature.region
      assert_equal "svc", signature.service
      assert_equal "PUT", signature.verb
      assert_equal uri, signature.uri
      assert_equal "hello", signature.body
      assert_equal "bar", signature.headers["foo"]
    end
  end

  describe "sign_headers" do
    let(:uri) { URI.parse("https://example.org/foo/bar?baz=blah") }

    it "should return signed headers" do
      headers = signer.sign_headers("PUT", uri, headers, "hello")

      %w(authorization x-amz-content-sha256).each do |name|
        assert headers.has_key?(name)
        assert headers[name].is_a?(String)
      end
    end
  end
end

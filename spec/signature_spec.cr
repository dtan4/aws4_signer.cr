require "./spec_helper"

require "http/headers"
require "uri"

describe Aws4Signer::Signature do
  let(:access_key_id) { "AKID" }
  let(:secret_access_key) { "SECRET" }
  let(:region) { "xx-region-1" }
  let(:service) { "svc" }
  let(:uri) { URI.parse("https://example.org/foo/bar?baz=blah") }
  let(:verb) { "PUT" }
  let(:headers) do
    h = HTTP::Headers.new
    h["x-foo"] = "bar"
    h
  end
  let(:body) { "hello" }
  let(:options) do
    {} of Symbol => String?
  end

  let(:signature) do
    Aws4Signer::Signature.new(
      access_key_id,
      secret_access_key,
      region,
      service,
      uri,
      verb,
      headers,
      body,
      options
    )
  end

  describe "headers" do
    describe "without x-amz-date" do
      it "should be assigned" do
        assert signature.headers["x-amz-date"].is_a?(String)
      end
    end

    describe "with x-amz-date" do

      before do
        headers["x-amz-date"] = "20151215T164227Z"
      end

      it "should not be assigned" do
        assert signature.headers["x-amz-date"].is_a?(String)
        assert_equal Time.new(2015, 12, 15, 16, 42, 27, 0, Time::Kind::Utc), signature.date
      end
    end

    describe "without host" do
      it "should be assigned" do
        assert_equal "example.org", signature.headers["Host"]
      end
    end

    describe "with host" do
      before do
        headers["host"] = "example.com"
      end

      it "should not be assigned" do
        assert_equal "example.com", signature.headers["Host"]
      end
    end

    describe "with security token" do
      let(:security_token) { "session_token" }

      let(:options) do
        { security_token: security_token }
      end

      it "should be assigned as x-amz-security-token" do
        assert_equal security_token, signature.headers["x-amz-security-token"]
      end
    end
  end

  describe "authorization_header" do
    before do
      headers["x-amz-date"] = "20140222T070605Z"
    end

    it "should return authorization_header" do
      assert_equal "AWS4-HMAC-SHA256 "\
        "Credential=AKID/20140222/xx-region-1/svc/aws4_request," \
        "SignedHeaders=host;x-amz-date;x-foo," \
        "Signature=2845eebf2510f52010a9d9e228d4b60d4dd33fb7e9f349fb21bd6a533bfc37b6",
        signature.authorization_header
    end
  end

  describe "canonical_headers" do
    let(:headers) do
      h = HTTP::Headers.new
      h["x-test-b"] = "2"
      h["X-Test-A"] = "1"
      h["x-test-c"] = "3"
      h["Authorization"] = "skip"
      h
    end

    it "should end with return" do
      assert_equal '\n', signature.canonical_headers.to_s[-1]
    end

    it "should contain headers" do
      assert signature.canonical_headers.to_s.lines.includes?("x-test-b:2\n")
      assert signature.canonical_headers.to_s.lines.includes?("x-test-a:1\n") # downcase
      assert signature.canonical_headers.to_s.lines.includes?("x-test-c:3\n")
      assert !signature.canonical_headers.to_s.lines.includes?("Authorization:skip\n")
    end

    it "should sort headers" do
      assert_equal %w(host x-amz-date x-test-a x-test-b x-test-c),
              signature.canonical_headers.to_s.lines.map { |line| line.split(/:/,2).first }
    end
  end

  describe "canonical_request" do
    before do
      headers["x-amz-date"] = "20140222T070605Z"
    end

    it "should return string to sign" do
      expected = <<-EXPECTED
PUT
/foo/bar
baz=blah
host:example.org
x-amz-date:20140222T070605Z
x-foo:bar

host;x-amz-date;x-foo
2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
EXPECTED
      assert_equal expected.chomp, signature.canonical_request
    end
  end

  describe "generate_signed_headers" do
    before do
      headers["x-amz-date"] = "20140222T070605Z"
    end

    it "should generate signed headers" do
      signed_headers = signature.generate_signed_headers

      assert_equal "example.org",  signed_headers["host"]
      assert_equal "20140222T070605Z",signed_headers["x-amz-date"]
      assert_equal "bar",signed_headers["x-foo"]
      assert_equal signature.authorization_header,signed_headers["authorization"]
      assert_equal "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", signed_headers["x-amz-content-sha256"]
    end
  end

  describe "hashed_payload" do
    let(:body) { "body" }

    it "should return hashed payload" do
      assert_equal "230d8358dc8e8890b4c58deeb62912ee2f20357ae92a5cc861b98e68fe31acb5", signature.hashed_payload
    end
  end

  describe "headers_hash" do
    let(:headers) do
      h = HTTP::Headers.new
      h["x-test-b"] = "2"
      h["X-Test-A"] = "1"
      h["x-test-c"] = "3"
      h["Authorization"] = "skip"
      h
    end

    it "should return Hash of headers" do
      headers_hash = signature.headers_hash

      assert_equal "2", headers_hash["x-test-b"]
      assert_equal "1", headers_hash["X-Test-A"]
      assert_equal "3", headers_hash["x-test-c"]
      assert_equal "skip", headers_hash["Authorization"]
    end
  end

  describe "scope" do
    before do
     headers["x-amz-date"] = "20140222T070605Z"
    end

    it "should return scope" do
      assert_equal "20140222/xx-region-1/svc/aws4_request", signature.scope
    end
  end

  describe "signature" do
    before do
      headers["x-amz-date"] = "20140222T070605Z"
    end

    it "return the sign" do
      assert_equal "2845eebf2510f52010a9d9e228d4b60d4dd33fb7e9f349fb21bd6a533bfc37b6", signature.signature
    end
  end

  describe "signed_headers" do
    let(:headers) do
      h = HTTP::Headers.new
      h["x-test-b"] = "2"
      h["X-Test-A"] = "1"
      h["x-test-c"] = "3"
      h["Authorization"] = "skip"
      h
    end

    it "should contain headers" do
      %w(x-test-a x-test-b x-test-c).each do |name|
        assert signature.signed_headers.to_s.split(';').includes?(name)
      end
    end

    it "should sort headers" do
      assert_equal "host;x-amz-date;x-test-a;x-test-b;x-test-c", signature.signed_headers
    end
  end

  describe "string_to_sign" do
    before do
      headers["x-amz-date"] = "20140222T070605Z"
    end

    it "should return string to sign" do
      expected = <<-EXPECTED
AWS4-HMAC-SHA256
20140222T070605Z
20140222/xx-region-1/svc/aws4_request
001733369d0e1b78643ae4a5c5a71afd8bf01e868a0835868b0b01a2c14ff3b2
EXPECTED
      assert_equal expected.chomp, signature.string_to_sign
    end
  end
end

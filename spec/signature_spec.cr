require "./spec_helper"

require "uri"

describe AwsSignerV4::Signature do
  let(:access_key_id) { "ACCESSKEYID" }
  let(:secret_access_key) { "SECRETACCESSKEY" }
  let(:region) { "ap-northeast-1" }
  let(:service) { "service" }
  let(:uri) { URI.parse("https://example.org/foo/bar?baz=blah") }
  let(:verb) { "PUT" }
  let(:headers) do
    { "x-foo" => "bar" } of String => String?
  end
  let(:body) { "body" }
  let(:options) do
    {} of Symbol => String?
  end

  let(:signature) do
    AwsSignerV4::Signature.new(
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
      let(:headers) do
        { "x-amz-date" => "20151215T164227Z" } of String => String?
      end

      it "should not be assigned" do
        assert signature.headers["x-amz-date"].is_a?(String)
        assert Time.new(2015, 12, 15, 16, 42, 27, 0, Time::Kind::Utc) == signature.date
      end
    end

    describe "without host" do
      it "should be assigned" do
        assert "example.org" == signature.headers["Host"]
      end
    end

    describe "with host" do
      let(:headers) do
        { "host" => "example.com" } of String => String?
      end

      it "should not be assigned" do
        assert "example.com" == signature.headers["Host"]
      end
    end

    describe "with security token" do
      let(:security_token) { "session_token" }

      let(:options) do
        { security_token: security_token }
      end

      it "should be assigned as x-amz-security-token" do
        assert security_token == signature.headers["x-amz-security-token"]
      end
    end
  end

  describe "scope" do
    before do
      headers["x-amz-date"] = "20140222T070605Z"
    end

    it "should return scope" do
      assert "20140222/ap-northeast-1/service/aws4_request" == signature.scope
    end
  end
end

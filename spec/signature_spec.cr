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
    {} of String => String?
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
  end
end

require "./spec_helper"

require "uri"

describe AwsSignerV4::Signature do
  access_key_id = "ACCESSKEYID"
  secret_access_key = "SECRETACCESSKEY"
  region = "ap-northeast-1"
  service = "service"
  uri = URI.parse("https://example.org/foo/bar?baz=blah")
  verb = "PUT"
  headers = { "x-foo" => "bar" } of String => String?
  body = "body"
  options = {} of String => String?

  signature = AwsSignerV4::Signature.new(
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

  describe "#headers" do
    context "without x-amz-date" do
      it "should be assigned" do
        signature.headers["x-amz-date"].is_a?(String).should eq true
      end
    end
  end
end

# aws4_signer.cr
[![Build Status](https://travis-ci.org/dtan4/aws4_signer.cr.svg?branch=master)](https://travis-ci.org/dtan4/aws4_signer.cr)

A simple library to sign AWS request using [AWS Signature Version 4](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html).

The implementation is inspired from [sorah/aws4_signer](https://github.com/sorah/aws4_signer).

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  aws4_signer:
    github: dtan4/aws4_signer.cr
```

## Usage

```crystal
require "aws4_signer"
```

### List objects in the specified S3 bucket

``` crystal
require "aws4_signer"
require "http/client"
require "uri"

bucket = "your-bucket"

signer = Aws4Signer.new(ENV["AWS_ACCESS_KEY_ID"], ENV["AWS_SECRET_ACCESS_KEY"], "ap-northeast-1", "s3")
uri = URI.parse("https://s3-ap-northeast-1.amazonaws.com/#{bucket}")

HTTP::Client.new(uri.host.to_s) do |client|
  headers = signer.sign_headers("GET", uri) ## ここでヘッダに認証情報を付与
  response = client.get(uri.path.to_s, headers)
  puts response.body
end
```

## Contributing

1. Fork it ( https://github.com/dtan4/aws4_signer.cr/fork )
2. Create your feature branch (git checkout -b my-new-feature)
3. Commit your changes (git commit -am 'Add some feature')
4. Push to the branch (git push origin my-new-feature)
5. Create a new Pull Request

## Contributors

- [@dtan4](https://github.com/dtan4) Daisuke Fujita - creator, maintainer

# gophlare

[![Twitter](https://img.shields.io/twitter/url?style=social&url=https%3A%2F%2Fgithub.com%2Fmr-pmillz%2Fgophlare)](https://twitter.com/intent/tweet?text=Wow:&url=https%3A%2F%2Fgithub.com%2Fmr-pmillz%2Fgophlare)
[![CI](https://github.com/mr-pmillz/gophlare/actions/workflows/ci.yml/badge.svg)](https://github.com/mr-pmillz/gophlare/actions/workflows/ci.yml)

## About

Gophlare is an SDK and CLI-wrapper for the flare.io API. It can be imported and used in other go projects.
Every API endpoint is not fully supported yet.

Gophlare also has several convenience features baked in such as:
1. XLSX and CSV file generation.
2. Stealer logs downloader for zip files or specific files.
3. Stealer logs cookies parser that can sort cookies by expiration date and CookieBro export to JSON support.
4. Getting credentials by domain name.
5. Hash identification for `hash` results that can differentiate between passwords, password hashes, and encrypted values.

## Supported API Endpoints

Gophlare currently supports the following API endpoints:

* /firework/v2/activities/{UID}
* /firework/v2/activities/{UID}/download
* /firework/v2/activities/{UID}/download_file
* [/firework/v4/events/global/_search](https://api.docs.flare.io/api-reference/v4/endpoints/global-search)
* [/leaksdb/v2/credentials/_search](https://api.docs.flare.io/api-reference/leaksdb/endpoints/post-credentials-search)
* [/leaksdb/v2/cookies/_search](https://api.docs.flare.io/api-reference/leaksdb/endpoints/post-cookies-search)

## Usage

```shell
Run search enumeration

Example Commands:
        gophlare search --config config.yaml

Usage:
  gophlare search [flags]

Flags:
  -c, --company string                  company name that your testing
  -d, --domain string                   domain string or file containing domains ex. domains.txt
  -e, --emails string                   emails to check in bulk. Can be a comma separated slice or a file containing emails. ex. emails.txt
  -f, --files-to-download string        comma separated list of files to match on and download if they exist from the query
  -h, --help                            help for search
      --keep-zip-files                  keep all the matching downloaded zip files from the stealer logs
  -m, --max-zip-download-limit int      maximum number of zip files to download from the stealer logs. Set to 0 to download all zip files. (default 50)
      --out-of-scope string             out of scope domains, IPs, or CIDRs
  -o, --output string                   report output dir
  -q, --query string                    query to use for searching stealer logs.
      --search-credentials-by-domain    search for credentials by domain
      --search-emails-in-bulk           search list of emails for credentials.
      --search-stealer-logs-by-domain   search the stealer logs by domain, download and parse all the matching zip files for passwords and live cookies
  -t, --timeout int                     timeout duration for API requests in seconds (default 600)
      --user-agent string               custom user-agent to use for requests (default "gophlare/")
  -u, --user-id-format string           if you know the user ID format ex. a12345 , include this to enhance matching in-scope results. can be a string, a file, or comma-separated list of strings
  -v, --verbose                         enable verbose output
  -y, --years int                       number of years in the past to search for stealer logs (default 2)

Global Flags:
      --config string   config file default location for viper to look is ~/.config/gophlare/config.yaml
      --configfileset   Used internally by gophlare to check if required args are set with and without configuration file, Do not use this flag...
```

### Configuration

The `USER_ID_FORMAT` option is a powerful feature to match account ID naming formats related to your target. For example, let's say your target uses account IDs with the format, `?l?d?d?d?d?d` , which would be one uppercase or lowercase letter followed by 5 digits, you could set the `USER_ID_FORMAT` in the config.yaml file like so:

```yaml
USER_ID_FORMAT: |-
  a12345
```

The preceding config will match any username with the regex pattern, `^[A-Za-z]\d{5}$` , sparing you the trouble of having to define the exact regex pattern. The function that does this is called, `IsUserIDFormatMatch` and can be found in the `utils` package in `string.go`. If desired, this feature could be extended to also except raw regex patterns also, but for ease of use, regex patterns are dynamically generated based on the USER_ID_FORMAT options provided. 

### Search Stealer Logs for Creds and Live Cookies

If you want to download and parse all matching stealer logs, set the `--max-zip-download-limit` to 0. Default is 50.
By default, this will search the stealer logs going back 2 years but you can adjust the years via the `--years` flag

```shell
gophlare search --config config.yaml --search-stealer-logs-by-domain --keep-zip-files --max-zip-download-limit 0 --years 3
```

### Search list of emails for leaked creds

```shell
./gophlare search --config config/config.yaml --search-emails-in-bulk -e emails.txt
```

### Search credentials api by domain for passwords

cli flags should override options set in config.yaml. For example, the following command will output results to the current directory via the `-o` option

```shell
./gophlare search --config config/config.yaml --search-credentials-by-domain -o .
```

## gophlare as a library

```go
package main

import (
	"github.com/mr-pmillz/gophlare"
)

// TODO
```

## ToDo

- [ ] Enhance cookies search
- [ ] Export cookies to separate cookie bro output JSON files per stealer log ID
- [ ] Implement remaining API endpoints
- [ ] Add example library usage to README.md
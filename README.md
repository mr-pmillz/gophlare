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
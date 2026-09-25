// Package tokens contains request and response models for Flare's
// /tokens/generate and /tokens/test endpoints.
//
// Flare documents these only as prose pages, so the models are generated from
// flareapi/openapi/tokens-openapi.yaml, a spec hand-authored from those pages.
// Regenerate with `make generate`.
package tokens

//go:generate go tool oapi-codegen -config oapi-codegen.yaml ../openapi/tokens-openapi.yaml

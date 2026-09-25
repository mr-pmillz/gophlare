// Package astp contains request and response models for Flare's Account &
// Session Takeover Prevention (ASTP) API, including the deprecated /leaksdb/
// endpoints.
//
// Flare documents ASTP only as prose pages, so the models are generated from
// flareapi/openapi/astp-openapi.yaml, a spec hand-authored from those pages.
// Regenerate with `make generate`.
package astp

//go:generate go tool oapi-codegen -config oapi-codegen.yaml ../openapi/astp-openapi.yaml

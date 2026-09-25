// Package fireworkv2 contains request and response models for Flare's
// Firework v2 API.
//
// models.gen.go is generated from Flare's published spec
// (flareapi/openapi/firework-v2-openapi.json). events.gen.go is generated from
// flareapi/openapi/firework-v2-events-openapi.yaml, a hand-authored supplement
// that types the stealer_log payload returned by GET /firework/v2/activities/,
// which the published spec leaves untyped.
//
// Refresh the published spec with `make openapi-specs` and regenerate with
// `make generate`.
package fireworkv2

//go:generate go tool oapi-codegen -config oapi-codegen.yaml ../openapi/firework-v2-openapi.json
//go:generate go tool oapi-codegen -config oapi-codegen-events.yaml ../openapi/firework-v2-events-openapi.yaml

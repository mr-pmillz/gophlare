package version

import (
	"runtime/debug"
	"testing"
)

func TestFromBuildInfo(t *testing.T) {
	tests := []struct {
		name string
		info *debug.BuildInfo
		want string
	}{
		{name: "no build info", want: "dev"},
		{name: "empty build info", info: &debug.BuildInfo{}, want: "dev"},
		{
			name: "installed release",
			info: &debug.BuildInfo{Main: debug.Module{Path: modulePath, Version: "v1.5.0"}},
			want: "v1.5.0",
		},
		{
			name: "local dirty build",
			info: &debug.BuildInfo{Main: debug.Module{Path: modulePath, Version: "v1.5.1-0.20260914120000-0123456789ab+dirty"}},
			want: "v1.5.1-0.20260914120000-0123456789ab+dirty",
		},
		{
			name: "devel build",
			info: &debug.BuildInfo{Main: debug.Module{Path: modulePath, Version: "(devel)"}},
			want: "dev",
		},
		{
			name: "empty module version",
			info: &debug.BuildInfo{Main: debug.Module{Path: modulePath}},
			want: "dev",
		},
		{
			name: "unrelated host version",
			info: &debug.BuildInfo{Main: debug.Module{Path: "example.com/app", Version: "v9.0.0"}},
			want: "dev",
		},
		{
			name: "SDK dependency",
			info: &debug.BuildInfo{
				Main: debug.Module{Path: "example.com/app", Version: "v9.0.0"},
				Deps: []*debug.Module{
					{Path: "example.com/other", Version: "v2.0.0"},
					{Path: modulePath, Version: "v1.5.0"},
				},
			},
			want: "v1.5.0",
		},
		{
			name: "replaced SDK dependency",
			info: &debug.BuildInfo{Deps: []*debug.Module{{
				Path: modulePath, Version: "v1.5.0",
				Replace: &debug.Module{Path: "example.com/fork", Version: "v1.6.0"},
			}}},
			want: "v1.6.0",
		},
		{
			name: "locally replaced SDK dependency",
			info: &debug.BuildInfo{Deps: []*debug.Module{{
				Path: modulePath, Version: "v1.5.0",
				Replace: &debug.Module{Path: "../gophlare"},
			}}},
			want: "dev",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fromBuildInfo(tt.info); got != tt.want {
				t.Errorf("version = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildVersionOverride(t *testing.T) {
	original := version
	t.Cleanup(func() { version = original })
	version = "v1.5.0-SNAPSHOT-test"
	if got := String(); got != version {
		t.Fatalf("version = %q, want injected version %q", got, version)
	}
	version = ""
	info, _ := debug.ReadBuildInfo()
	if got, want := String(), fromBuildInfo(info); got != want {
		t.Fatalf("version = %q, want build metadata %q", got, want)
	}
}

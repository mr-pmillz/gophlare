package utils

import (
	"path/filepath"
	"testing"
)

func TestIsPathSafe(t *testing.T) {
	tests := []struct {
		name     string
		baseDir  string
		filePath string
		wantSafe bool
		wantErr  bool
	}{
		{
			name:     "safe path - file in base directory",
			baseDir:  "/tmp/extract",
			filePath: "/tmp/extract/file.txt",
			wantSafe: true,
			wantErr:  false,
		},
		{
			name:     "safe path - file in subdirectory",
			baseDir:  "/tmp/extract",
			filePath: "/tmp/extract/subdir/file.txt",
			wantSafe: true,
			wantErr:  false,
		},
		{
			name:     "safe path - deeply nested",
			baseDir:  "/tmp/extract",
			filePath: "/tmp/extract/a/b/c/d/file.txt",
			wantSafe: true,
			wantErr:  false,
		},
		{
			name:     "unsafe path - parent directory escape",
			baseDir:  "/tmp/extract",
			filePath: "/tmp/extract/../etc/passwd",
			wantSafe: false,
			wantErr:  false,
		},
		{
			name:     "unsafe path - multiple parent escapes",
			baseDir:  "/tmp/extract",
			filePath: "/tmp/extract/../../../etc/passwd",
			wantSafe: false,
			wantErr:  false,
		},
		{
			name:     "unsafe path - sibling directory with shared prefix",
			baseDir:  "/tmp/extract-123",
			filePath: "/tmp/extract-1234/malicious.txt",
			wantSafe: false,
			wantErr:  false,
		},
		{
			name:     "unsafe path - completely outside",
			baseDir:  "/tmp/extract",
			filePath: "/etc/passwd",
			wantSafe: false,
			wantErr:  false,
		},
		{
			name:     "unsafe path - just parent",
			baseDir:  "/tmp/extract",
			filePath: "/tmp",
			wantSafe: false,
			wantErr:  false,
		},
		{
			name:     "safe path - base directory itself",
			baseDir:  "/tmp/extract",
			filePath: "/tmp/extract",
			wantSafe: true,
			wantErr:  false,
		},
		{
			name:     "safe path - relative notation resolving inside",
			baseDir:  "/tmp/extract",
			filePath: "/tmp/extract/subdir/../file.txt",
			wantSafe: true,
			wantErr:  false,
		},
		{
			name:     "unsafe path - hidden escape in middle",
			baseDir:  "/tmp/extract",
			filePath: "/tmp/extract/subdir/../../etc/passwd",
			wantSafe: false,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSafe, err := isPathSafe(tt.baseDir, tt.filePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("isPathSafe() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotSafe != tt.wantSafe {
				// Show resolved paths for debugging
				absBase, _ := filepath.Abs(tt.baseDir)
				absFile, _ := filepath.Abs(tt.filePath)
				rel, _ := filepath.Rel(absBase, absFile)
				t.Errorf("isPathSafe() = %v, want %v\n  baseDir: %s\n  filePath: %s\n  absBase: %s\n  absFile: %s\n  rel: %s",
					gotSafe, tt.wantSafe, tt.baseDir, tt.filePath, absBase, absFile, rel)
			}
		})
	}
}

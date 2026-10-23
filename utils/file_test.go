package utils

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/xuri/excelize/v2"
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

func TestCSVFileRoundTrip(test *testing.T) {
	type record struct {
		ID      uint64 `csv:"id"`
		Value   string `csv:"value"`
		Enabled bool   `csv:"enabled"`
	}
	want := []record{
		{ID: 9007199254740993, Value: "fixture, \"quoted\"\n東京", Enabled: true},
		{ID: 0, Value: "", Enabled: false},
		{ID: 7, Value: "0010", Enabled: false},
	}
	filename := filepath.Join(test.TempDir(), "nested", "records.csv")
	if err := WriteStructToCSVFile(want, filename); err != nil {
		test.Fatal(err)
	}
	var actual []record
	if err := UnmarshalCSVFile(filename, &actual); err != nil {
		test.Fatal(err)
	}
	if !slices.Equal(actual, want) {
		test.Fatalf("CSV round trip: got %#v, want %#v", actual, want)
	}
}

func TestUnmarshalCSVFileNumbers(test *testing.T) {
	for _, fixture := range []struct {
		name      string
		value     string
		want      uint8
		wantError bool
	}{
		{"zero", "0", 0, false},
		{"decimal leading zero", "010", 10, false},
		{"non-octal digit", "09", 9, false},
		{"maximum", "255", 255, false},
		{"overflow", "256", 0, true},
		{"negative unsigned", "-1", 0, true},
	} {
		test.Run(fixture.name, func(test *testing.T) {
			filename := filepath.Join(test.TempDir(), "records.csv")
			if err := os.WriteFile(filename, []byte("value\n"+fixture.value+"\n"), 0600); err != nil {
				test.Fatal(err)
			}
			var records []struct {
				Value uint8 `csv:"value"`
			}
			err := UnmarshalCSVFile(filename, &records)
			if (err != nil) != fixture.wantError {
				test.Fatalf("decode error=%v, wantError=%v", err, fixture.wantError)
			}
			if !fixture.wantError && (len(records) != 1 || records[0].Value != fixture.want) {
				test.Fatalf("decoded records=%v, want value=%d", records, fixture.want)
			}
		})
	}
}

func TestCSVsToExcel(test *testing.T) {
	test.Parallel()
	directory := test.TempDir()
	csvFile := filepath.Join(directory, "credentials.csv")
	contents := "id,name\n9007199254740993,\"東京, sample\"\n0007,\"line one\nline two\"\n"
	if err := os.WriteFile(csvFile, []byte(contents), 0600); err != nil {
		test.Fatal(err)
	}
	workbookFile := filepath.Join(directory, "report.xlsx")
	if err := CSVsToExcel([]string{csvFile}, workbookFile); err != nil {
		test.Fatal(err)
	}
	workbook, err := excelize.OpenFile(workbookFile)
	if err != nil {
		test.Fatal(err)
	}
	defer func() {
		if err := workbook.Close(); err != nil {
			test.Error(err)
		}
	}()
	rows, err := workbook.GetRows("credentials")
	if err != nil {
		test.Fatal(err)
	}
	want := [][]string{{"id", "name"}, {"9007199254740993", "東京, sample"}, {"0007", "line one\nline two"}}
	if !reflect.DeepEqual(rows, want) {
		test.Fatalf("spreadsheet changed CSV values: got %#v, want %#v", rows, want)
	}
	tables, err := workbook.GetTables("credentials")
	if err != nil || len(tables) != 1 || tables[0].Range != "A1:B3" {
		test.Fatalf("spreadsheet table=%+v, error=%v", tables, err)
	}
}

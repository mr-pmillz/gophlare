package utils

import (
	"archive/zip"
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/gocarina/gocsv"
	"github.com/xuri/excelize/v2"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ResolveAbsPath ...
func ResolveAbsPath(path string) (string, error) {
	usr, err := user.Current()
	if err != nil {
		return path, err
	}

	dir := usr.HomeDir
	if path == "~" {
		path = dir
	} else if strings.HasPrefix(path, "~/") {
		path = filepath.Join(dir, path[2:])
	}

	path, err = filepath.Abs(path)
	if err != nil {
		return path, err
	}

	return path, nil
}

// Exists returns whether the given file or directory exists
func Exists(path string) (bool, error) {
	if path == "" {
		return false, nil
	}
	absPath, err := ResolveAbsPath(path)
	if err != nil {
		return false, err
	}
	info, err := os.Stat(absPath)
	if err == nil {
		switch {
		case info.IsDir():
			return true, nil
		case info.Size() >= 0:
			// file exists but it's empty
			return true, nil
		}
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// ReadLines reads a whole file into memory
// and returns a slice of its lines.
func ReadLines(path string) ([]string, error) {
	var lines []string
	absPath, err := ResolveAbsPath(path)
	if err != nil {
		return nil, LogError(err)
	}
	exists, err := Exists(absPath)
	if err != nil {
		return nil, LogError(err)
	}
	if !exists {
		LogWarningf("File does not exist, cannot read lines for non-existent file: %s", absPath)
		return lines, nil
	}

	file, err := os.Open(absPath)
	if err != nil {
		return nil, LogError(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// WriteLines writes the lines to the given file.
func WriteLines(lines []string, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return LogError(err)
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	for _, line := range lines {
		if len(line) > 0 {
			_, _ = fmt.Fprintln(w, line)
		}
	}
	return w.Flush()
}

// UnzipToTemp extracts a ZIP file to a temporary directory and returns the absolute paths of the extracted files.
func UnzipToTemp(zipPath string) ([]string, string, error) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to open zip file: %w", err)
	}
	defer r.Close()

	tempDir, err := os.MkdirTemp("", "unzipped-*")
	if err != nil {
		return nil, "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Ensure tempDir is cleaned up on failure
	defer func() {
		if err != nil {
			_ = os.RemoveAll(tempDir)
		}
	}()

	var extractedFiles []string
	for _, f := range r.File {
		filePath := filepath.Join(tempDir, f.Name) //nolint:gosec

		// Ensure the file path is within the destination directory to prevent traversal
		if safe, pathErr := isPathSafe(tempDir, filePath); !safe {
			return nil, "", fmt.Errorf("unsafe path detected: %s, error: %w", filePath, pathErr)
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(filePath, os.ModePerm); err != nil {
				return nil, "", fmt.Errorf("failed to create directory: %w", err)
			}
			continue
		}

		if err = os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
			return nil, "", fmt.Errorf("failed to create directory structure: %w", err)
		}

		outFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return nil, "", fmt.Errorf("failed to create file: %w", err)
		}

		rc, err := f.Open()
		if err != nil {
			_ = outFile.Close()
			return nil, "", fmt.Errorf("failed to open zipped file: %w", err)
		}

		if _, err := io.Copy(outFile, rc); err != nil { //nolint:gosec
			_ = outFile.Close()
			_ = rc.Close()
			return nil, "", fmt.Errorf("failed to copy file content: %w", err)
		}

		_ = outFile.Close()
		_ = rc.Close()

		absPath, err := filepath.Abs(filePath)
		if err != nil {
			return nil, "", fmt.Errorf("failed to get absolute path: %w", err)
		}

		extractedFiles = append(extractedFiles, absPath)
	}

	return extractedFiles, tempDir, nil
}

// isPathSafe ensures the resultant file path is confined to the base directory
func isPathSafe(baseDir, filePath string) (bool, error) {
	absBaseDir, err := filepath.Abs(baseDir)
	if err != nil {
		return false, fmt.Errorf("failed to get absolute path of base directory: %w", err)
	}
	absFilePath, err := filepath.Abs(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to get absolute path of file: %w", err)
	}
	return strings.HasPrefix(absFilePath, absBaseDir), nil
}

// WriteStructToJSONFile ...
func WriteStructToJSONFile(data interface{}, outputFile string) error {
	outputFileDir := filepath.Dir(outputFile)
	if err := os.MkdirAll(outputFileDir, 0750); err != nil {
		return LogError(err)
	}

	f, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return LogError(err)
	}

	if err = os.WriteFile(outputFile, f, 0644); err != nil { //nolint:gosec
		return LogError(err)
	}
	return nil
}

// WriteStructToCSVFile ...
func WriteStructToCSVFile(data interface{}, outputFile string) error {
	outputFileDir := filepath.Dir(outputFile)
	if err := os.MkdirAll(outputFileDir, 0750); err != nil {
		return LogError(err)
	}

	file, err := os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return LogError(err)
	}
	defer file.Close()

	err = gocsv.MarshalFile(data, file)
	if err != nil {
		return LogError(err)
	}

	return nil
}

// shortenStringSheetName takes a spreadsheet worksheet name and shortens it to ensure the max 31 char limit is not exceeded.
func shortenStringSheetName(str string, index int) string {
	if len(str) > 31 {
		// shorten to 27 + _ + index to support edge case where 100 or more csv files..
		return str[:27] + "_" + strconv.Itoa(index)
	}
	return str
}

// CSVsToExcel ...
func CSVsToExcel(csvFiles []string, output string) error {
	// Filter out non-existing CSV files
	var existingAndNonEmptyFiles []string
	for _, csvFile := range csvFiles {
		if exists, err := Exists(csvFile); exists && err == nil {
			if !IsFileEmpty(csvFile) {
				existingAndNonEmptyFiles = append(existingAndNonEmptyFiles, csvFile)
			}
		}
	}
	if len(existingAndNonEmptyFiles) == 0 {
		LogWarningf("The specified CSV files do not exist: %s", strings.Join(csvFiles, "\n"))
		return nil
	}

	InfoLabelf("Excel", "Creating new Excel .xlsx spreadsheet for the following CSV files:\n%s", strings.Join(existingAndNonEmptyFiles, "\n"))
	f := excelize.NewFile()
	var counter int
	totalCsvFiles := len(existingAndNonEmptyFiles)
	for i, csvFile := range existingAndNonEmptyFiles {
		counter++
		sheetName := shortenStringSheetName(SanitizeString(strings.TrimSuffix(filepath.Base(csvFile), ".csv")), i)
		index, err := f.NewSheet(sheetName)
		if err != nil {
			return LogError(err)
		}

		if err = processCSVFile(f, csvFile, sheetName); err != nil {
			return LogError(err)
		}

		f.SetActiveSheet(index)
		fmt.Printf("[+] Completed %d/%d \n", counter, totalCsvFiles)
	}
	if err := f.DeleteSheet("Sheet1"); err != nil {
		return LogError(err)
	}
	if err := f.SaveAs(output); err != nil {
		return LogError(err)
	}
	InfoLabelf("Excel", "Successfully created new Excel spreadsheet: %s", output)
	return nil
}

// IsFileEmpty ...
func IsFileEmpty(filePath string) bool {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		// Could not obtain the file info, possibly because the file doesn't exist.
		return true
	}

	// File is empty if its size is 0.
	return fileInfo.Size() == 0
}

func processCSVFile(f *excelize.File, csvFile string, sheetName string) error {
	file, err := os.Open(csvFile)
	if err != nil {
		return err
	}
	defer file.Close()

	csvReader := csv.NewReader(file)
	csvReader.LazyQuotes = true
	csvReader.Comma = ','
	csvReader.FieldsPerRecord = -1

	reader := gocsv.NewSimpleDecoderFromCSVReader(csvReader)
	records, err := reader.GetCSVRows()
	if err != nil {
		return err
	}

	if len(records) == 0 {
		LogWarningf("csv file: %s is empty. On to the next...", csvFile)
		return nil
	}
	numRows := len(records)
	numCols := len(records[0])

	// Set the table options
	cellName, err := excelize.CoordinatesToCellName(numCols, numRows)
	if err != nil {
		return LogError(err)
	}
	tableOptions := &excelize.Table{
		Range:             fmt.Sprintf("A1:%s", cellName),
		Name:              "_" + sheetName,
		StyleName:         "TableStyleMedium7",
		ShowColumnStripes: false,
		ShowFirstColumn:   false,
		ShowHeaderRow:     nil,
		ShowLastColumn:    false,
		ShowRowStripes:    nil,
	}

	for row, record := range records {
		for col, value := range record {
			cell, _ := excelize.CoordinatesToCellName(col+1, row+1)
			if err = f.SetCellValue(sheetName, cell, value); err != nil {
				return LogError(err)
			}
		}
	}
	// set column widths
	if err := setColWidths(f, sheetName); err != nil {
		return LogError(err)
	}

	// Add the table to the sheet
	return f.AddTable(sheetName, tableOptions)
}

// setColWidths auto-fits column widths for spreadsheet with a max of 40
func setColWidths(f *excelize.File, sheetName string) error {
	cols, err := f.GetCols(sheetName)
	if err != nil {
		return err
	}
	for idx, col := range cols {
		largestWidth := 0
		for _, rowCell := range col {
			cellWidth := utf8.RuneCountInString(rowCell) + 3 // + 2 for margin
			if cellWidth > largestWidth {
				largestWidth = cellWidth
			}
		}
		name, err := excelize.ColumnNumberToName(idx + 1)
		if err != nil {
			return LogError(err)
		}
		if largestWidth >= 50 {
			largestWidth = 50
		}
		err = f.SetColWidth(sheetName, name, name, float64(largestWidth))
		if err != nil {
			return LogError(err)
		}
	}
	return nil
}

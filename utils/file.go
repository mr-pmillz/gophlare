package utils

import (
	"archive/zip"
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gocarina/gocsv"
	"github.com/xuri/excelize/v2"
)

// GzipCompressFile compresses the file specified by the srcPath and writes it to a file specified by dstPath.
func GzipCompressFile(srcPath, dstPath string) error {
	// Open the source file for reading.
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return LogError(err)
	}
	defer srcFile.Close()

	// Create the destination file for writing.
	dstFile, err := os.Create(dstPath)
	if err != nil {
		return LogError(err)
	}
	defer dstFile.Close()

	// Create a gzip writer on top of the destination file.
	gzipWriter := gzip.NewWriter(dstFile)
	defer gzipWriter.Close()

	// Specify a buffer size.
	// You might want to experiment with this size to find the best performance for your specific case.
	bufferSize := 64 * 1024 // 64 KB

	// Create a buffer of the specified size.
	buf := make([]byte, bufferSize)

	// Copy the contents of the source file to the gzip writer using the buffer.
	_, err = io.CopyBuffer(gzipWriter, srcFile, buf)
	if err != nil {
		return LogError(err)
	}

	return nil
}

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

// UnmarshalCSVFile ...
func UnmarshalCSVFile(filePath string, data interface{}) error {
	file, err := os.Open(filePath)
	if err != nil {
		return LogError(err)
	}
	defer file.Close()

	gocsv.SetCSVReader(func(in io.Reader) gocsv.CSVReader {
		r := csv.NewReader(in)
		r.LazyQuotes = true
		r.Comma = ','
		r.FieldsPerRecord = -1
		return r
	})

	if err = gocsv.UnmarshalFile(file, data); err != nil {
		return LogError(err)
	}
	return nil
}

// UnmarshalJSONLines ...
func UnmarshalJSONLines(inputFile string, outStruct interface{}) (interface{}, error) {
	t := reflect.TypeOf(outStruct)
	if t.Kind() != reflect.Struct {
		return nil, fmt.Errorf("provided interface is not a struct")
	}

	file, err := os.Open(inputFile)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	slice := reflect.MakeSlice(reflect.SliceOf(t), 0, 0)

	for {
		line, isPrefix, err := reader.ReadLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading line: %w", err)
		}

		var completeLine []byte
		completeLine = append(completeLine, line...)
		for isPrefix {
			line, isPrefix, err = reader.ReadLine()
			if err != nil {
				return nil, fmt.Errorf("error reading line continuation: %w", err)
			}
			completeLine = append(completeLine, line...)
		}

		itemPtr := reflect.New(t).Interface()
		if err := json.Unmarshal(completeLine, itemPtr); err != nil {
			return nil, fmt.Errorf("error unmarshaling JSON: %w", err)
		}

		slice = reflect.Append(slice, reflect.ValueOf(itemPtr).Elem())
	}

	return slice.Interface(), nil
}

// UnmarshalJSONFile unmarshal a JSON file into a struct
func UnmarshalJSONFile(filePath string, v interface{}) error {
	f, err := os.Open(filePath)
	if err != nil {
		return LogError(err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return LogError(err)
	}

	if err = json.Unmarshal(data, v); err != nil {
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

// CopyFile ...
func CopyFile(src, dest string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return LogError(err)
	}
	defer srcFile.Close()

	if err = os.MkdirAll(filepath.Dir(dest), 0750); err != nil {
		return LogError(err)
	}

	destFile, err := os.Create(dest)
	if err != nil {
		return LogError(err)
	}
	defer destFile.Close()

	buf := make([]byte, 1024*1024*4)
	_, err = io.CopyBuffer(destFile, srcFile, buf)
	if err != nil {
		return LogError(err)
	}
	return nil
}

// WriteInterfaceToCSV writes arbitrary interface data to a CSV file.
// It works with:
// - Slices of structs (with support for nested structs)
// - Single struct (with support for nested structs)
// - Maps (with string keys)
// - Slices of maps
//
// The function flattens nested structures so that each string field gets its own column.
func WriteInterfaceToCSV(data interface{}, outputCSVFilePath string) error {
	// Create or truncate the output file
	file, err := os.Create(outputCSVFilePath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	// Create a CSV writer
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Use reflection to examine the data
	val := reflect.ValueOf(data)
	typ := val.Type()

	// Handle pointer types
	if typ.Kind() == reflect.Ptr {
		if val.IsNil() {
			return errors.New("nil pointer provided")
		}
		val = val.Elem()
		typ = val.Type()
	}

	// Handle different data types
	switch {
	case typ.Kind() == reflect.Slice && typ.Elem().Kind() == reflect.Struct:
		// Handle slice of structs
		return writeStructSliceToCSV(val, writer)
	case typ.Kind() == reflect.Struct:
		// Handle single struct
		return writeSingleStructToCSV(val, writer)
	case typ.Kind() == reflect.Map:
		// Handle single map
		return writeMapToCSV(val, writer)
	case typ.Kind() == reflect.Slice && typ.Elem().Kind() == reflect.Map:
		// Handle slice of maps
		return writeMapSliceToCSV(val, writer)
	default:
		return errors.New("unsupported data type: must be struct, slice of structs, map, or slice of maps")
	}
}

// writeStructSliceToCSV handles a slice of structs with nested struct support
func writeStructSliceToCSV(val reflect.Value, writer *csv.Writer) error {
	if val.Len() == 0 {
		return errors.New("empty slice provided")
	}

	// Get the first element to determine structure
	firstElem := val.Index(0)

	// Get flattened headers
	headers, err := getFlattenedHeaders(firstElem)
	if err != nil {
		return err
	}

	// Write headers
	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("error writing headers: %w", err)
	}

	// Write each row
	for i := 0; i < val.Len(); i++ {
		row, err := getFlattenedValues(val.Index(i), headers)
		if err != nil {
			return fmt.Errorf("error extracting values for row %d: %w", i, err)
		}

		if err := writer.Write(row); err != nil {
			return fmt.Errorf("error writing row %d: %w", i, err)
		}
	}

	return nil
}

// writeSingleStructToCSV handles a single struct with nested struct support
func writeSingleStructToCSV(val reflect.Value, writer *csv.Writer) error {
	// Get flattened headers
	headers, err := getFlattenedHeaders(val)
	if err != nil {
		return err
	}

	// Write headers
	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("error writing headers: %w", err)
	}

	// Get flattened values
	row, err := getFlattenedValues(val, headers)
	if err != nil {
		return fmt.Errorf("error extracting values: %w", err)
	}

	// Write the struct values
	if err := writer.Write(row); err != nil {
		return fmt.Errorf("error writing row: %w", err)
	}

	return nil
}

// writeMapToCSV handles a single map
//
//nolint:gocognit
func writeMapToCSV(val reflect.Value, writer *csv.Writer) error {
	if val.Type().Key().Kind() != reflect.String {
		return errors.New("map key must be string")
	}

	// Get map keys
	keys := val.MapKeys()

	// Convert keys to strings for headers
	headers := make([]string, 0, len(keys))
	for _, key := range keys {
		keyStr := key.String()
		mapVal := val.MapIndex(key)

		// Check if this is a nested structure
		if mapVal.Kind() == reflect.Struct || (mapVal.Kind() == reflect.Ptr && !mapVal.IsNil() && mapVal.Elem().Kind() == reflect.Struct) {
			var structVal reflect.Value
			if mapVal.Kind() == reflect.Ptr {
				structVal = mapVal.Elem()
			} else {
				structVal = mapVal
			}

			// Get nested headers
			nestedHeaders, err := getFlattenedHeaders(structVal)
			if err != nil {
				return err
			}

			// Prefix with a parent key
			for _, nestedHeader := range nestedHeaders {
				headers = append(headers, keyStr+"."+nestedHeader)
			}
		} else {
			headers = append(headers, keyStr)
		}
	}

	// Write headers
	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("error writing headers: %w", err)
	}

	// Extract values based on headers
	row := make([]string, len(headers))
	for i, header := range headers {
		parts := strings.Split(header, ".")
		keyVal := reflect.ValueOf(parts[0])

		if !val.MapIndex(keyVal).IsValid() {
			row[i] = ""
			continue
		}

		mapVal := val.MapIndex(keyVal)

		// Handle nested fields
		if len(parts) > 1 {
			// Skip if nil
			if mapVal.Kind() == reflect.Ptr && mapVal.IsNil() {
				row[i] = ""
				continue
			}

			// Get the nested value
			if mapVal.Kind() == reflect.Ptr {
				mapVal = mapVal.Elem()
			}

			fieldVal, err := getNestedFieldValue(mapVal, parts[1:])
			if err != nil {
				row[i] = ""
			} else {
				row[i] = fmt.Sprintf("%v", fieldVal)
			}
		} else {
			row[i] = fmt.Sprintf("%v", mapVal.Interface())
		}
	}

	// Write values
	if err := writer.Write(row); err != nil {
		return fmt.Errorf("error writing row: %w", err)
	}

	return nil
}

// writeMapSliceToCSV handles a slice of maps with nested struct support
//
//nolint:gocognit
func writeMapSliceToCSV(val reflect.Value, writer *csv.Writer) error {
	if val.Len() == 0 {
		return errors.New("empty slice provided")
	}

	// Check first map
	firstMap := val.Index(0)
	if firstMap.Type().Key().Kind() != reflect.String {
		return errors.New("map keys must be strings")
	}

	// Collect all unique headers across all maps, including nested structures
	allHeaders := make(map[string]bool)

	for i := 0; i < val.Len(); i++ {
		mapVal := val.Index(i)
		keys := mapVal.MapKeys()

		for _, key := range keys {
			keyStr := key.String()
			fieldVal := mapVal.MapIndex(key)

			// Check for nested structures
			if fieldVal.Kind() == reflect.Struct || (fieldVal.Kind() == reflect.Ptr && !fieldVal.IsNil() && fieldVal.Elem().Kind() == reflect.Struct) {
				var structVal reflect.Value
				if fieldVal.Kind() == reflect.Ptr {
					structVal = fieldVal.Elem()
				} else {
					structVal = fieldVal
				}

				// Get nested headers
				nestedHeaders, err := getFlattenedHeaders(structVal)
				if err != nil {
					continue
				}

				// Add with prefix
				for _, nestedHeader := range nestedHeaders {
					allHeaders[keyStr+"."+nestedHeader] = true
				}
			} else {
				allHeaders[keyStr] = true
			}
		}
	}

	// Convert to headers slice
	headers := make([]string, 0, len(allHeaders))
	for header := range allHeaders {
		headers = append(headers, header)
	}

	// Write headers
	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("error writing headers: %w", err)
	}

	// Write each map as a row
	for i := 0; i < val.Len(); i++ {
		mapVal := val.Index(i)
		row := make([]string, len(headers))

		// Populate row with values for each header
		for j, header := range headers {
			parts := strings.Split(header, ".")
			key := reflect.ValueOf(parts[0])

			if !mapVal.MapIndex(key).IsValid() {
				row[j] = ""
				continue
			}

			fieldVal := mapVal.MapIndex(key)

			// Handle nested fields
			if len(parts) > 1 {
				// Skip if nil
				if fieldVal.Kind() == reflect.Ptr && fieldVal.IsNil() {
					row[j] = ""
					continue
				}

				// Get nested value
				if fieldVal.Kind() == reflect.Ptr {
					fieldVal = fieldVal.Elem()
				}

				nestedVal, err := getNestedFieldValue(fieldVal, parts[1:])
				if err != nil {
					row[j] = ""
				} else {
					row[j] = fmt.Sprintf("%v", nestedVal)
				}
			} else {
				row[j] = fmt.Sprintf("%v", fieldVal.Interface())
			}
		}

		if err := writer.Write(row); err != nil {
			return fmt.Errorf("error writing row %d: %w", i, err)
		}
	}

	return nil
}

// getFlattenedHeaders returns flattened header names from a struct value
func getFlattenedHeaders(val reflect.Value) ([]string, error) {
	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			return nil, errors.New("nil pointer provided")
		}
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return nil, fmt.Errorf("expected struct, got %s", val.Kind())
	}

	var headers []string
	typ := val.Type()

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)

		// Skip unexported fields
		if field.PkgPath != "" {
			continue
		}

		fieldName := field.Name
		// Check for csv tag (optional enhancement)
		tag := field.Tag.Get("csv")
		if tag != "" && tag != "-" {
			fieldName = tag
		}

		fieldType := field.Type
		fieldValue := val.Field(i)

		// Handle pointer types
		if fieldType.Kind() == reflect.Ptr {
			if fieldValue.IsNil() {
				// Add the field as is if it's nil
				headers = append(headers, fieldName)
				continue
			}
			fieldType = fieldType.Elem()
			fieldValue = fieldValue.Elem()
		}

		// Recurse into nested structs
		if fieldType.Kind() == reflect.Struct {
			// Handle time.Time specially
			if fieldType.String() == "time.Time" {
				headers = append(headers, fieldName)
				continue
			}

			nestedHeaders, err := getFlattenedHeaders(fieldValue)
			if err != nil {
				return nil, err
			}

			// Prefix nested headers with parent field name
			for _, nestedHeader := range nestedHeaders {
				headers = append(headers, fieldName+"."+nestedHeader)
			}
		} else {
			headers = append(headers, fieldName)
		}
	}

	return headers, nil
}

// getFlattenedValues extracts values from a struct based on flattened headers
func getFlattenedValues(val reflect.Value, headers []string) ([]string, error) {
	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			return nil, errors.New("nil pointer provided")
		}
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return nil, fmt.Errorf("expected struct, got %s", val.Kind())
	}

	result := make([]string, len(headers))

	for i, header := range headers {
		parts := strings.Split(header, ".")
		fieldVal, err := getNestedFieldValue(val, parts)
		if err != nil {
			result[i] = "" // Empty string for missing or nil fields
		} else {
			result[i] = fmt.Sprintf("%v", fieldVal)
		}
	}

	return result, nil
}

// getNestedFieldValue retrieves a value from nested structs using dot notation
func getNestedFieldValue(val reflect.Value, fieldPath []string) (interface{}, error) {
	if len(fieldPath) == 0 {
		return val.Interface(), nil
	}

	if val.Kind() != reflect.Struct {
		return nil, fmt.Errorf("expected struct, got %s", val.Kind())
	}

	fieldName := fieldPath[0]
	field := val.FieldByName(fieldName)

	if !field.IsValid() {
		// Try to find field by csv tag
		found := false
		valType := val.Type()
		for i := 0; i < valType.NumField(); i++ {
			structField := valType.Field(i)
			if tag := structField.Tag.Get("csv"); tag == fieldName {
				field = val.Field(i)
				found = true
				break
			}
		}

		if !found {
			return nil, fmt.Errorf("field %s not found", fieldName)
		}
	}

	// Handle nil pointers
	if field.Kind() == reflect.Ptr && field.IsNil() {
		return nil, errors.New("nil pointer in nested field")
	}

	// Dereference pointer if needed
	if field.Kind() == reflect.Ptr {
		field = field.Elem()
	}

	if len(fieldPath) == 1 {
		return field.Interface(), nil
	}

	// Continue recursion for nested fields
	return getNestedFieldValue(field, fieldPath[1:])
}

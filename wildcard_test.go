package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestContainsWildcard(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"file.pcap", false},
		{"*.pcap", true},
		{"file?.pcap", true},
		{"file[1-3].pcap", true},
		{"/path/to/file.pcap", false},
		{"/path/to/*.pcap", true},
	}

	for _, test := range tests {
		result := containsWildcard(test.path)
		if result != test.expected {
			t.Errorf("containsWildcard(%q) = %v; want %v", test.path, result, test.expected)
		}
	}
}

func TestExpandWildcards(t *testing.T) {
	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "joincap-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create some test files
	testFiles := []string{
		"file1.pcap",
		"file2.pcap",
		"file3.txt",
		"other_file.pcap",
	}

	for _, name := range testFiles {
		path := filepath.Join(tempDir, name)
		if err := os.WriteFile(path, []byte("test"), 0o644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", name, err)
		}
	}

	// Test with wildcard pattern
	pattern := filepath.Join(tempDir, "*.pcap")
	expandedPaths := ExpandWildcards([]string{pattern}, false)

	// Verify results
	if len(expandedPaths) != 3 {
		t.Errorf("Expected 3 files to match wildcard, got %d", len(expandedPaths))
	}

	expectedFiles := []string{
		filepath.Join(tempDir, "file1.pcap"),
		filepath.Join(tempDir, "file2.pcap"),
		filepath.Join(tempDir, "other_file.pcap"),
	}

	// Check that each expected file is in the expanded paths
	for _, expectedFile := range expectedFiles {
		found := false
		for _, expandedFile := range expandedPaths {
			if expandedFile == expectedFile {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected file %s not found in expanded paths", expectedFile)
		}
	}

	// Test with non-wildcard pattern
	regularFile := filepath.Join(tempDir, "file1.pcap")
	expandedPaths = ExpandWildcards([]string{regularFile}, false)

	if len(expandedPaths) != 1 {
		t.Errorf("Expected 1 file with non-wildcard path, got %d", len(expandedPaths))
	}

	if expandedPaths[0] != regularFile {
		t.Errorf("Expected %s, got %s", regularFile, expandedPaths[0])
	}

	// Test with non-matching wildcard
	nonMatchingPattern := filepath.Join(tempDir, "nomatch*.pcap")
	expandedPaths = ExpandWildcards([]string{nonMatchingPattern}, false)

	if len(expandedPaths) != 1 {
		t.Errorf("Expected original pattern when no matches found, got %d paths", len(expandedPaths))
	}

	if expandedPaths[0] != nonMatchingPattern {
		t.Errorf("Expected original pattern %s, got %s", nonMatchingPattern, expandedPaths[0])
	}

	// Test with multiple patterns
	multiplePatterns := []string{
		filepath.Join(tempDir, "file*.pcap"),
		filepath.Join(tempDir, "other*.pcap"),
	}

	expandedPaths = ExpandWildcards(multiplePatterns, false)

	if len(expandedPaths) != 3 {
		t.Errorf("Expected 3 files with multiple patterns, got %d", len(expandedPaths))
	}
}

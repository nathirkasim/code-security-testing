package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
)

// SafeResolvePath resolves user input against baseDir and checks for Path Traversal (CWE-22).
func SafeResolvePath(baseDir string, userSubpath string) (string, error) {
	cleanBase := filepath.Clean(baseDir)
	targetPath := filepath.Clean(filepath.Join(cleanBase, userSubpath))

	// Ensure target path starts with cleanBase directory prefix
	rel, err := filepath.Rel(cleanBase, targetPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("access denied: path traversal attempt detected")
	}

	return targetPath, nil
}

// GenerateSecureToken creates a cryptographically secure random hex token (CWE-330).
func GenerateSecureToken(byteLength int) (string, error) {
	if byteLength < 16 {
		byteLength = 16
	}
	bytes := make([]byte, byteLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

package main

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// JamfConfig holds the Jamf Pro configuration
type JamfConfig struct {
	URL      string
	Username string
	Password string
}

// Global configuration variables
var (
	jamfURL      string
	jamfUsername string
	jamfPassword string
	auditLogger  *log.Logger
)

// initAuditLogger initializes the audit logger to write to jamf_extractor.log
func initAuditLogger() error {
	logFile, err := os.OpenFile("jamf_extractor.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open audit log file: %w", err)
	}

	// Create a multi-writer to write to both file and stdout
	multiWriter := io.MultiWriter(logFile, os.Stdout)

	auditLogger = log.New(multiWriter, "", log.LstdFlags)

	// Log the start of a new session
	auditLogger.Printf("=== Jamf Extractor Session Started ===")
	auditLogger.Printf("Timestamp: %s", time.Now().Format(time.RFC3339))
	auditLogger.Printf("Version: 1.0.0")
	auditLogger.Printf("Working Directory: %s", getCurrentDir())

	return nil
}

// getCurrentDir returns the current working directory
func getCurrentDir() string {
	dir, err := os.Getwd()
	if err != nil {
		return "unknown"
	}
	return dir
}

// AuthResponse represents the response from the authentication endpoint
type AuthResponse struct {
	Token string `json:"token"`
}

// ComputerRecord represents the computer inventory data from Classic API
type ComputerRecord struct {
	XMLName xml.Name `xml:"computer"`
	General struct {
		SerialNumber string `xml:"serial_number"`
		UDID         string `xml:"udid"`
	} `xml:"general"`
	Hardware struct {
		Make  string `xml:"make"`
		Model string `xml:"model"`
	} `xml:"hardware"`
}

// FileVaultResponse represents the FileVault recovery key response
type FileVaultResponse struct {
	PersonalRecoveryKey string `json:"personalRecoveryKey"`
}

// ComputerListItem represents a computer in the list from Jamf Pro API
type ComputerListItem struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ComputerListResponse represents the response from the computers list endpoint
type ComputerListResponse struct {
	TotalCount int                `json:"totalCount"`
	Results    []ComputerListItem `json:"results"`
}

// ReportRow represents a single row in the TSV report
type ReportRow struct {
	JamfProID             string
	Make                  string
	Model                 string
	SerialNumber          string
	UDID                  string
	FileVaultKeyAvailable string
	FileVaultRecoveryKey  string
	JamfProURL            string
}

// JamfClient handles API interactions with Jamf Pro
type JamfClient struct {
	config     JamfConfig
	token      string
	httpClient *http.Client
}

// NewJamfClient creates a new Jamf API client
func NewJamfClient(config JamfConfig) *JamfClient {
	return &JamfClient{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Authenticate gets a bearer token from Jamf Pro
func (c *JamfClient) Authenticate() error {
	url := strings.TrimSuffix(c.config.URL, "/") + "/api/v1/auth/token"

	auditLogger.Printf("AUTH: Attempting authentication to %s with user %s", c.config.URL, c.config.Username)

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		auditLogger.Printf("AUTH: Failed to create auth request: %v", err)
		return fmt.Errorf("failed to create auth request: %w", err)
	}

	req.SetBasicAuth(c.config.Username, c.config.Password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		auditLogger.Printf("AUTH: Failed to authenticate: %v", err)
		return fmt.Errorf("failed to authenticate: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		auditLogger.Printf("AUTH: Authentication failed with status: %d", resp.StatusCode)
		return fmt.Errorf("authentication failed with status: %d", resp.StatusCode)
	}

	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		auditLogger.Printf("AUTH: Failed to decode auth response: %v", err)
		return fmt.Errorf("failed to decode auth response: %w", err)
	}

	c.token = authResp.Token
	auditLogger.Printf("AUTH: Successfully authenticated, token obtained")
	return nil
}

// CheckTokenValidity verifies if the current token is valid
func (c *JamfClient) CheckTokenValidity() error {
	url := strings.TrimSuffix(c.config.URL, "/") + "/api/v1/auth"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create token check request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to check token validity: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token check failed with status: %d", resp.StatusCode)
	}

	return nil
}

// RenewToken renews the current bearer token
func (c *JamfClient) RenewToken() error {
	url := strings.TrimSuffix(c.config.URL, "/") + "/api/v1/auth/keep-alive"

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create token renewal request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to renew token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token renewal failed with status: %d", resp.StatusCode)
	}

	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return fmt.Errorf("failed to decode token renewal response: %w", err)
	}

	c.token = authResp.Token
	return nil
}

// CheckAndRenewToken checks token validity and renews if necessary
func (c *JamfClient) CheckAndRenewToken() error {
	if err := c.CheckTokenValidity(); err != nil {
		// Token is invalid, get a new one
		return c.Authenticate()
	}

	// Token is valid, try to renew it
	if err := c.RenewToken(); err != nil {
		// If renewal fails, get a new token
		return c.Authenticate()
	}

	return nil
}

// GetComputerList retrieves a list of all computers from Jamf Pro API
func (c *JamfClient) GetComputerList(page int, pageSize int) (*ComputerListResponse, error) {
	url := strings.TrimSuffix(c.config.URL, "/") + "/api/v1/computers-inventory"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create computer list request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	// Add query parameters for pagination
	q := req.URL.Query()
	q.Add("page", strconv.Itoa(page))
	q.Add("page-size", strconv.Itoa(pageSize))
	req.URL.RawQuery = q.Encode()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get computer list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get computer list with status: %d", resp.StatusCode)
	}

	var computerList ComputerListResponse
	if err := json.NewDecoder(resp.Body).Decode(&computerList); err != nil {
		return nil, fmt.Errorf("failed to decode computer list response: %w", err)
	}

	return &computerList, nil
}

// GetAllComputerIDs retrieves all computer IDs from Jamf Pro API with pagination
func (c *JamfClient) GetAllComputerIDs() ([]string, error) {
	auditLogger.Printf("COMPUTER_LIST: Starting to retrieve all computer IDs from Jamf Pro")

	var allIDs []string
	page := 0
	pageSize := 100 // Jamf Pro API supports up to 200 per page

	for {
		// Check and renew token before each request
		if err := c.CheckAndRenewToken(); err != nil {
			auditLogger.Printf("COMPUTER_LIST: Failed to authenticate for page %d: %v", page, err)
			return nil, fmt.Errorf("failed to authenticate: %w", err)
		}

		auditLogger.Printf("COMPUTER_LIST: Fetching page %d (page size: %d)", page, pageSize)

		computerList, err := c.GetComputerList(page, pageSize)
		if err != nil {
			auditLogger.Printf("COMPUTER_LIST: Failed to get computer list for page %d: %v", page, err)
			return nil, fmt.Errorf("failed to get computer list for page %d: %w", page, err)
		}

		// Add IDs from this page
		for _, computer := range computerList.Results {
			allIDs = append(allIDs, computer.ID)
		}

		auditLogger.Printf("COMPUTER_LIST: Page %d returned %d computers (total so far: %d)", page, len(computerList.Results), len(allIDs))

		// Check if we've got all computers
		if len(computerList.Results) < pageSize {
			break
		}

		page++
	}

	auditLogger.Printf("COMPUTER_LIST: Successfully retrieved %d total computer IDs", len(allIDs))
	return allIDs, nil
}

// GetComputerRecord retrieves computer inventory data using Classic API
func (c *JamfClient) GetComputerRecord(id string) (*ComputerRecord, error) {
	url := strings.TrimSuffix(c.config.URL, "/") + "/JSSResource/computers/id/" + id

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create computer record request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/xml")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get computer record: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get computer record with status: %d", resp.StatusCode)
	}

	var computerRecord ComputerRecord
	if err := xml.NewDecoder(resp.Body).Decode(&computerRecord); err != nil {
		return nil, fmt.Errorf("failed to decode computer record: %w", err)
	}

	return &computerRecord, nil
}

// CheckFileVaultKeyAvailability checks if a FileVault recovery key is available
func (c *JamfClient) CheckFileVaultKeyAvailability(id string) (bool, error) {
	url := strings.TrimSuffix(c.config.URL, "/") + "/api/v1/computers-inventory/" + id + "/filevault"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create FileVault check request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to check FileVault key availability: %w", err)
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK, nil
}

// GetFileVaultRecoveryKey retrieves the FileVault recovery key
func (c *JamfClient) GetFileVaultRecoveryKey(id string) (string, error) {
	url := strings.TrimSuffix(c.config.URL, "/") + "/api/v1/computers-inventory/" + id + "/filevault"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create FileVault key request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get FileVault recovery key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get FileVault recovery key with status: %d", resp.StatusCode)
	}

	var fileVaultResp FileVaultResponse
	if err := json.NewDecoder(resp.Body).Decode(&fileVaultResp); err != nil {
		return "", fmt.Errorf("failed to decode FileVault response: %w", err)
	}

	return fileVaultResp.PersonalRecoveryKey, nil
}

// ProcessComputerID processes a single computer ID and returns report data
func (c *JamfClient) ProcessComputerID(id string) (*ReportRow, error) {
	auditLogger.Printf("PROCESS: Starting to process computer ID %s", id)

	// Validate ID is numeric
	if _, err := strconv.Atoi(id); err != nil {
		auditLogger.Printf("PROCESS: Invalid computer ID format: %s", id)
		return nil, fmt.Errorf("invalid computer ID: %s", id)
	}

	// Check and renew token
	if err := c.CheckAndRenewToken(); err != nil {
		auditLogger.Printf("PROCESS: Failed to authenticate for computer ID %s: %v", id, err)
		return nil, fmt.Errorf("failed to authenticate: %w", err)
	}

	// Get computer record
	auditLogger.Printf("PROCESS: Retrieving computer record for ID %s", id)
	computerRecord, err := c.GetComputerRecord(id)
	if err != nil {
		auditLogger.Printf("PROCESS: Failed to get computer record for ID %s: %v", id, err)
		return nil, fmt.Errorf("failed to get computer record for ID %s: %w", id, err)
	}

	auditLogger.Printf("PROCESS: Retrieved computer record - Make: %s, Model: %s, Serial: %s",
		computerRecord.Hardware.Make, computerRecord.Hardware.Model, computerRecord.General.SerialNumber)

	// Check FileVault key availability
	auditLogger.Printf("PROCESS: Checking FileVault key availability for ID %s", id)
	keyAvailable, err := c.CheckFileVaultKeyAvailability(id)
	if err != nil {
		auditLogger.Printf("PROCESS: Failed to check FileVault key availability for ID %s: %v", id, err)
		return nil, fmt.Errorf("failed to check FileVault key availability for ID %s: %w", id, err)
	}

	var fileVaultKey string
	var keyAvailableStr string

	if keyAvailable {
		keyAvailableStr = "Yes"
		auditLogger.Printf("PROCESS: FileVault key available for ID %s, retrieving key", id)
		key, err := c.GetFileVaultRecoveryKey(id)
		if err != nil {
			auditLogger.Printf("PROCESS: Error retrieving FileVault key for ID %s: %v", id, err)
			fileVaultKey = "Error retrieving FileVault recovery key"
		} else if key == "" {
			auditLogger.Printf("PROCESS: Empty FileVault key returned for ID %s", id)
			fileVaultKey = "Error retrieving FileVault recovery key"
		} else {
			auditLogger.Printf("PROCESS: Successfully retrieved FileVault key for ID %s", id)
			fileVaultKey = key
		}
	} else {
		keyAvailableStr = "No"
		fileVaultKey = "NA"
		auditLogger.Printf("PROCESS: No FileVault key available for ID %s", id)
	}

	jamfProURL := strings.TrimSuffix(c.config.URL, "/") + "/computers.html?id=" + id

	auditLogger.Printf("PROCESS: Successfully processed computer ID %s", id)

	return &ReportRow{
		JamfProID:             id,
		Make:                  computerRecord.Hardware.Make,
		Model:                 computerRecord.Hardware.Model,
		SerialNumber:          computerRecord.General.SerialNumber,
		UDID:                  computerRecord.General.UDID,
		FileVaultKeyAvailable: keyAvailableStr,
		FileVaultRecoveryKey:  fileVaultKey,
		JamfProURL:            jamfProURL,
	}, nil
}

// WriteCSVReport writes the report data to a CSV file
func WriteCSVReport(reportRows []ReportRow, filename string) error {
	auditLogger.Printf("REPORT: Creating CSV report with %d rows at %s", len(reportRows), filename)

	file, err := os.Create(filename)
	if err != nil {
		auditLogger.Printf("REPORT: Failed to create report file %s: %v", filename, err)
		return fmt.Errorf("failed to create report file: %w", err)
	}
	defer file.Close()

	// Write header
	header := "Jamf Pro ID Number,Make,Model,Serial Number,UDID,FileVault Recovery Key Available,FileVault Recovery Key,Jamf Pro URL\n"
	if _, err := file.WriteString(header); err != nil {
		auditLogger.Printf("REPORT: Failed to write header to %s: %v", filename, err)
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write data rows
	for i, row := range reportRows {
		line := fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s\n",
			escapeCSVField(row.JamfProID),
			escapeCSVField(row.Make),
			escapeCSVField(row.Model),
			escapeCSVField(row.SerialNumber),
			escapeCSVField(row.UDID),
			escapeCSVField(row.FileVaultKeyAvailable),
			escapeCSVField(row.FileVaultRecoveryKey),
			escapeCSVField(row.JamfProURL),
		)
		if _, err := file.WriteString(line); err != nil {
			auditLogger.Printf("REPORT: Failed to write row %d to %s: %v", i+1, filename, err)
			return fmt.Errorf("failed to write report row: %w", err)
		}
	}

	auditLogger.Printf("REPORT: Successfully created CSV report with %d rows at %s", len(reportRows), filename)
	return nil
}

// escapeCSVField properly escapes CSV fields that contain commas, quotes, or newlines
func escapeCSVField(field string) string {
	// If field contains comma, quote, or newline, wrap in quotes and escape internal quotes
	if strings.Contains(field, ",") || strings.Contains(field, "\"") || strings.Contains(field, "\n") {
		// Escape internal quotes by doubling them
		escaped := strings.ReplaceAll(field, "\"", "\"\"")
		return "\"" + escaped + "\""
	}
	return field
}

// ReadComputerIDs reads computer IDs from a file
func ReadComputerIDs(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var ids []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			ids = append(ids, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return ids, nil
}

// ShowProgress displays a simple progress indicator
func ShowProgress(current, total int) {
	percentage := float64(current) / float64(total) * 100
	fmt.Printf("\rProcessing: %d/%d (%.1f%%)", current, total, percentage)
}

// processComputers is the main processing logic
func processComputers(computerIDs []string, config JamfConfig) {
	auditLogger.Printf("MAIN: Starting to process %d computer IDs", len(computerIDs))
	auditLogger.Printf("MAIN: Jamf Pro URL: %s", config.URL)
	auditLogger.Printf("MAIN: Username: %s", config.Username)

	// Create Jamf client
	client := NewJamfClient(config)

	// Authenticate
	fmt.Println("Authenticating with Jamf Pro...")
	auditLogger.Printf("MAIN: Initiating authentication")
	if err := client.Authenticate(); err != nil {
		auditLogger.Printf("MAIN: Authentication failed: %v", err)
		log.Fatalf("Failed to authenticate: %v", err)
	}
	fmt.Println("Authentication successful!")
	auditLogger.Printf("MAIN: Authentication successful")

	// Process computer IDs
	fmt.Printf("Processing %d computer IDs...\n", len(computerIDs))
	auditLogger.Printf("MAIN: Starting to process %d computer IDs", len(computerIDs))

	var reportRows []ReportRow
	successCount := 0
	errorCount := 0

	for i, id := range computerIDs {
		ShowProgress(i+1, len(computerIDs))

		row, err := client.ProcessComputerID(id)
		if err != nil {
			auditLogger.Printf("MAIN: Error processing ID %s: %v", id, err)
			log.Printf("Error processing ID %s: %v", id, err)
			errorCount++
			continue
		}

		reportRows = append(reportRows, *row)
		successCount++
	}

	fmt.Println() // New line after progress
	auditLogger.Printf("MAIN: Processing complete - Success: %d, Errors: %d", successCount, errorCount)

	// Generate report
	if len(reportRows) > 0 {
		reportFile := filepath.Join(os.TempDir(), fmt.Sprintf("filevault_report_%d.csv", time.Now().Unix()))

		if err := WriteCSVReport(reportRows, reportFile); err != nil {
			auditLogger.Printf("MAIN: Failed to write report: %v", err)
			log.Fatalf("Failed to write report: %v", err)
		}

		fmt.Printf("Report generated successfully!\n")
		fmt.Printf("File location: %s\n", reportFile)
		fmt.Printf("Successfully processed: %d computers\n", successCount)
		if errorCount > 0 {
			fmt.Printf("Errors encountered: %d computers\n", errorCount)
		}

		auditLogger.Printf("MAIN: Report generation complete - File: %s, Rows: %d", reportFile, len(reportRows))
	} else {
		fmt.Println("No data to report")
		auditLogger.Printf("MAIN: No data to report - no successful computer processing")
	}

	auditLogger.Printf("MAIN: Session completed successfully")
}

func main() {
	// Initialize audit logger
	if err := initAuditLogger(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize audit logger: %v\n", err)
		os.Exit(1)
	}

	var rootCmd = &cobra.Command{
		Use:   "jamf-extractor",
		Short: "Extract FileVault recovery keys from Jamf Pro",
		Long: `A tool to extract FileVault recovery keys from Jamf Pro computers.
This tool can process all computers in your Jamf Pro instance or specific computers from a file.`,
	}

	// Global flags with environment variable support
	rootCmd.PersistentFlags().StringVarP(&jamfURL, "url", "u", "", "Jamf Pro server URL (required, or set JAMF_URL env var)")
	rootCmd.PersistentFlags().StringVarP(&jamfUsername, "username", "n", "", "Jamf Pro username (required, or set JAMF_USERNAME env var)")
	rootCmd.PersistentFlags().StringVarP(&jamfPassword, "password", "p", "", "Jamf Pro password (required, or set JAMF_PASSWORD env var)")

	// Bind environment variables
	rootCmd.PersistentFlags().Lookup("url").NoOptDefVal = os.Getenv("JAMF_URL")
	rootCmd.PersistentFlags().Lookup("username").NoOptDefVal = os.Getenv("JAMF_USERNAME")
	rootCmd.PersistentFlags().Lookup("password").NoOptDefVal = os.Getenv("JAMF_PASSWORD")

	// Set default values from environment variables
	if jamfURL == "" {
		jamfURL = os.Getenv("JAMF_URL")
	}
	if jamfUsername == "" {
		jamfUsername = os.Getenv("JAMF_USERNAME")
	}
	if jamfPassword == "" {
		jamfPassword = os.Getenv("JAMF_PASSWORD")
	}

	// Mark required flags only if not set via environment variables
	if jamfURL == "" {
		rootCmd.MarkPersistentFlagRequired("url")
	}
	if jamfUsername == "" {
		rootCmd.MarkPersistentFlagRequired("username")
	}
	if jamfPassword == "" {
		rootCmd.MarkPersistentFlagRequired("password")
	}

	// All computers command
	var allCmd = &cobra.Command{
		Use:   "all",
		Short: "Process all computers from Jamf Pro",
		Long:  `Get all computers from Jamf Pro and extract their FileVault recovery keys.`,
		Run: func(cmd *cobra.Command, args []string) {
			auditLogger.Printf("COMMAND: 'all' command executed")

			config := JamfConfig{
				URL:      jamfURL,
				Username: jamfUsername,
				Password: jamfPassword,
			}

			// Create Jamf client
			client := NewJamfClient(config)

			// Authenticate
			fmt.Println("Authenticating with Jamf Pro...")
			if err := client.Authenticate(); err != nil {
				auditLogger.Printf("COMMAND: Authentication failed in 'all' command: %v", err)
				log.Fatalf("Failed to authenticate: %v", err)
			}
			fmt.Println("Authentication successful!")

			// Get all computer IDs
			fmt.Println("Getting all computer IDs from Jamf Pro...")
			computerIDs, err := client.GetAllComputerIDs()
			if err != nil {
				auditLogger.Printf("COMMAND: Failed to get computer IDs in 'all' command: %v", err)
				log.Fatalf("Failed to get computer IDs from Jamf Pro: %v", err)
			}
			fmt.Printf("Found %d computers in Jamf Pro\n", len(computerIDs))

			processComputers(computerIDs, config)
		},
	}

	// File command
	var fileCmd = &cobra.Command{
		Use:   "file [filename]",
		Short: "Process computers from a file containing IDs",
		Long:  `Process computers from a text file containing one Jamf Pro computer ID per line.`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			filename := args[0]
			auditLogger.Printf("COMMAND: 'file' command executed with file: %s", filename)

			// Read computer IDs from file
			computerIDs, err := ReadComputerIDs(filename)
			if err != nil {
				auditLogger.Printf("COMMAND: Failed to read computer IDs from file %s: %v", filename, err)
				log.Fatalf("Failed to read computer IDs: %v", err)
			}

			if len(computerIDs) == 0 {
				auditLogger.Printf("COMMAND: No computer IDs found in file %s", filename)
				log.Fatal("No computer IDs found in file")
			}

			auditLogger.Printf("COMMAND: Successfully read %d computer IDs from file %s", len(computerIDs), filename)

			config := JamfConfig{
				URL:      jamfURL,
				Username: jamfUsername,
				Password: jamfPassword,
			}

			processComputers(computerIDs, config)
		},
	}

	// Add commands to root
	rootCmd.AddCommand(allCmd)
	rootCmd.AddCommand(fileCmd)

	// Add completion command
	rootCmd.AddCommand(&cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate completion script",
		Long: `To load completions:

Bash:
  $ source <(jamf-extractor completion bash)

  # To load completions for each session, execute once:
  # Linux:
  $ jamf-extractor completion bash > /etc/bash_completion.d/jamf-extractor
  # macOS:
  $ jamf-extractor completion bash > /usr/local/etc/bash_completion.d/jamf-extractor

Zsh:
  $ source <(jamf-extractor completion zsh)

  # To load completions for each session, execute once:
  $ jamf-extractor completion zsh > "${fpath[1]}/_jamf-extractor"

Fish:
  $ jamf-extractor completion fish | source

  # To load completions for each session, execute once:
  $ jamf-extractor completion fish > ~/.config/fish/completions/jamf-extractor.fish

PowerShell:
  PS> jamf-extractor completion powershell | Out-String | Invoke-Expression

  # To load completions for each session, execute once:
  PS> jamf-extractor completion powershell > jamf-extractor.ps1
  # and source this file from your PowerShell profile.
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.ExactValidArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			switch args[0] {
			case "bash":
				cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				cmd.Root().GenPowerShellCompletion(os.Stdout)
			}
		},
	})

	// Execute
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

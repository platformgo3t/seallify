package licensingclient

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/denisbrodbeck/machineid"
)

const StorageFile = "license.dat"

// Config It contains all the parameters that the library consumer must provide.
type Config struct {
	ApiActivateURL string
	ApiValidateURL string
	// EncryptionKey: 32-byte key for AES-256 (MANDATORY)
	EncryptionKey []byte
	// ValidationInterval: Frequency with which the server is checked (heartbeat).
	ValidationInterval time.Duration
	// AppID: Unique application identifier to generate the Machine ID.
	AppID string
}

type LicenseManager struct {
	Config         Config
	CurrentToken   string
	MachineID      string
	LicenseKey     string
	IsValid        bool
	ExpiresAt      time.Time
	AllowedModules []string
}

type EncryptedLicenseData struct {
	Token          string    `json:"token"`
	LicenseKey     string    `json:"license_key"`
	ExpiresAt      time.Time `json:"expires_at"`
	AllowedModules []string  `json:"allowed_modules"`
}

type ClientLicenseRequest struct {
	LicenseKey string `json:"license_key"`
	MachineID  string `json:"machine_id"`
}

type ClientLicenseResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	Status    string `json:"status"`
	Modules   string `json:"modules"`
}

type NetworkError struct {
	msg string
}

func (e *NetworkError) Error() string {
	return e.msg
}

// getMachineID generates and returns a unique machine ID, using the AppID from the configuration.
func (mgr *LicenseManager) getMachineID() (string, error) {
	return machineid.ProtectedID(mgr.Config.AppID)
}

// Encrypt encrypts the data using AES-GCM
func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt the data using AES-GCM.
func Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, encryptedData := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// saveLicenseData encrypts and saves the key, token, modules, and expiration to a local file.
func (mgr *LicenseManager) saveLicenseData() error {
	dataToSave := EncryptedLicenseData{
		Token:          mgr.CurrentToken,
		LicenseKey:     mgr.LicenseKey,
		ExpiresAt:      mgr.ExpiresAt,
		AllowedModules: mgr.AllowedModules,
	}

	jsonData, err := json.Marshal(dataToSave)
	if err != nil {
		return fmt.Errorf("Error serializing JSON: %w", err)
	}

	encryptedBytes, err := Encrypt(jsonData, mgr.Config.EncryptionKey)
	if err != nil {
		return fmt.Errorf("Error encrypting data: %w", err)
	}

	encodedData := base64.StdEncoding.EncodeToString(encryptedBytes)

	err = os.WriteFile(StorageFile, []byte(encodedData), 0600)
	if err != nil {
		return fmt.Errorf("Error writing license file: %w", err)
	}

	log.Println("🔑 License data encrypted and stored in", StorageFile)
	return nil
}

// loadLicenseData loads and decrypts the key, token, modules, and expiration from the local file.
func (mgr *LicenseManager) loadLicenseData() error {
	content, err := os.ReadFile(StorageFile)
	if err != nil {
		return fmt.Errorf("license file not found or inaccessible: %w", err)
	}

	encryptedBytes, err := base64.StdEncoding.DecodeString(string(content))
	if err != nil {
		return fmt.Errorf("Base64 decoding error: %w", err)
	}

	decryptedBytes, err := Decrypt(encryptedBytes, mgr.Config.EncryptionKey)
	if err != nil {
		return fmt.Errorf("Error decrypting data (corrupted key or file): %w", err)
	}

	var loadedData EncryptedLicenseData
	if err := json.Unmarshal(decryptedBytes, &loadedData); err != nil {
		return fmt.Errorf("Error deserializing JSON: %w", err)
	}

	// Cargar los datos en el manager
	mgr.CurrentToken = loadedData.Token
	mgr.LicenseKey = loadedData.LicenseKey
	mgr.ExpiresAt = loadedData.ExpiresAt
	mgr.AllowedModules = loadedData.AllowedModules

	log.Println("🔑 License data successfully uploaded from", StorageFile)
	return nil
}

func (mgr *LicenseManager) parseAndSetModules(modulesJSON string) {
	var modules []string
	if err := json.Unmarshal([]byte(modulesJSON), &modules); err != nil {
		log.Printf("Warning: JSON module deserialization failed: %v", err)
		mgr.AllowedModules = []string{"error"} // Default
	} else {
		mgr.AllowedModules = modules
	}
}

func (mgr *LicenseManager) parseAndSetExpiration(expiresAtStr string) {
	t, err := time.Parse(time.RFC3339, expiresAtStr)
	if err != nil {
		log.Printf("Warning: Expiration date parsing failed: %v", err)
		mgr.ExpiresAt = time.Time{}
	} else {
		mgr.ExpiresAt = t
	}
}

// validateToken performs periodic checks (Heartbeat) with the server.
func (mgr *LicenseManager) validateToken() error {
	log.Println("--- STARTING LICENSE CHECK-IN ---")
	if mgr.CurrentToken == "" {
		mgr.IsValid = false
		return fmt.Errorf("No token saved. Persistence system failure")
	}

	req, err := http.NewRequest("POST", mgr.Config.ApiValidateURL, nil)
	if err != nil {
		mgr.IsValid = false
		return err
	}

	req.Header.Add("Authorization", "Bearer "+mgr.CurrentToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)

	if err != nil {
		mgr.IsValid = false
		// Return NetworkError to activate the grace period
		return &NetworkError{msg: fmt.Sprintf("error de red al validar: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		mgr.IsValid = false
		var errorMsg bytes.Buffer
		errorMsg.ReadFrom(resp.Body)
		// Returns server error (no grace period applies)
		return fmt.Errorf("validación fallida (HTTP %d): %s", resp.StatusCode, errorMsg.String())
	}

	var response ClientLicenseResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		mgr.IsValid = false
		return fmt.Errorf("error al decodificar la respuesta de validación: %w", err)
	}

	// The server responds OK: YOUR STATE PREVAILS, we update the expiration and validate.
	mgr.parseAndSetExpiration(response.ExpiresAt)
	mgr.parseAndSetModules(response.Modules)

	mgr.CurrentToken = response.Token
	mgr.IsValid = true
	log.Println("✅ Check-in successful. Token renewed. Continue using.")

	if err := mgr.saveLicenseData(); err != nil {
		log.Printf("Warning: The encrypted license file could not be saved after renewal: %v", err)
	}
	return nil
}

// startValidationLoop -- Start periodic license checks in the background.
func (mgr *LicenseManager) startValidationLoop() {
	ticker := time.NewTicker(mgr.Config.ValidationInterval)
	defer ticker.Stop()

	for range ticker.C {
		err := mgr.validateToken()
		if err != nil {
			log.Printf("⛔ NEWSPAPER LICENSE ERROR: %v", err)
			mgr.IsValid = false

			if _, isNetError := err.(*NetworkError); isNetError {
				// LOGIC OF THE GRACE PERIOD IN THE BACKGROUND
				if time.Now().Before(mgr.ExpiresAt) {
					log.Println("⚠️ Maintaining active with a grace period (NETWORK FAILURE).")
					mgr.IsValid = true
				} else {
					log.Println("🚨 GRACE PERIOD EXPIRED. Blocking functionality.")
					mgr.IsValid = false
				}
			} else {
				log.Println("🚨 SERVER REJECTION. Immediately blocking functionality.")
				mgr.IsValid = false
			}
		}
	}
}

func NewManager(cfg Config) (*LicenseManager, error) {
	mgr := &LicenseManager{
		Config: cfg,
	}

	var err error
	mgr.MachineID, err = mgr.getMachineID()
	if err != nil {
		return nil, fmt.Errorf("Error obtaining Machine ID: %w", err)
	}

	loadErr := mgr.loadLicenseData()
	if loadErr != nil {
		log.Printf("INFO:The encrypted license could not be loaded. Initial activation is required.: %v", loadErr)
		// Leaving mgr.CurrentToken empty forces activation
	} else {
		log.Println("License loaded. Attempting to validate token...")
		validationErr := mgr.validateToken()

		if validationErr != nil {
			log.Printf("⛔ VALIDATION FAILED: %v", validationErr)

			if _, isNetError := validationErr.(*NetworkError); isNetError {
				// Período de gracia si hay error de red
				if time.Now().Before(mgr.ExpiresAt) {
					mgr.IsValid = true
					log.Println("⚠️ Using local grace period (NETWORK FAILURE).")
				} else {
					return nil, fmt.Errorf("Locally expired token and connection failure: the application with limited options.")
				}
			} else {
				return nil, fmt.Errorf("server validation rejection: %w", validationErr)
			}
		}
	}

	// Start periodic background checks
	go mgr.startValidationLoop()

	return mgr, nil
}

func (mgr *LicenseManager) Activate(licenseKey string) error {
	mgr.LicenseKey = licenseKey

	reqBody := ClientLicenseRequest{LicenseKey: mgr.LicenseKey, MachineID: mgr.MachineID}
	jsonBody, _ := json.Marshal(reqBody)

	resp, err := http.Post(mgr.Config.ApiActivateURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("Connection error with the license server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorMsg bytes.Buffer
		errorMsg.ReadFrom(resp.Body)
		return fmt.Errorf("activation failed (HTTP %d): %s", resp.StatusCode, errorMsg.String())
	}

	var response ClientLicenseResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("error decoding activation response: %w", err)
	}

	mgr.parseAndSetExpiration(response.ExpiresAt)
	mgr.parseAndSetModules(response.Modules)

	mgr.CurrentToken = response.Token
	mgr.IsValid = true
	log.Println("✅ License successfully activated. Token obtained and modules updated..")

	if err := mgr.saveLicenseData(); err != nil {
		log.Printf("Warning: The encrypted license file could not be saved.: %v", err)
	}
	return nil
}

func (mgr *LicenseManager) CheckModule(moduleName string) bool {
	if !mgr.IsValid {
		return false
	}
	for _, module := range mgr.AllowedModules {
		if module == moduleName {
			return true
		}
	}
	return false
}

func (mgr *LicenseManager) GetStatus() bool {
	return mgr.IsValid
}

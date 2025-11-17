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

// StorageFile define el nombre del archivo de persistencia local (cifrado)
const StorageFile = "license.dat"

// --- ESTRUCTURAS DE DATOS EXPORTADAS Y CONFIGURABLES ---

// Config contiene todos los parámetros que el consumidor de la librería debe proveer.
type Config struct {
	ApiActivateURL string
	ApiValidateURL string
	// EncryptionKey: Clave de 32 bytes para AES-256 (MANDATORIA)
	EncryptionKey []byte
	// ValidationInterval: Frecuencia con la que se hace el chequeo (heartbeat) al servidor.
	ValidationInterval time.Duration
	// AppID: Identificador único de la aplicación para generar el Machine ID.
	AppID string
}

// LicenseManager gestiona el estado de la licencia y el almacenamiento seguro.
type LicenseManager struct {
	Config         Config
	CurrentToken   string
	MachineID      string
	LicenseKey     string
	IsValid        bool
	ExpiresAt      time.Time
	AllowedModules []string
}

// EncryptedLicenseData es la estructura que se almacena en el archivo (cifrada).
type EncryptedLicenseData struct {
	Token          string    `json:"token"`
	LicenseKey     string    `json:"license_key"`
	ExpiresAt      time.Time `json:"expires_at"`
	AllowedModules []string  `json:"allowed_modules"`
}

// ClientLicenseRequest estructura para enviar al servidor.
type ClientLicenseRequest struct {
	LicenseKey string `json:"license_key"`
	MachineID  string `json:"machine_id"`
}

// ClientLicenseResponse es la respuesta del servidor.
type ClientLicenseResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	Status    string `json:"status"`
	Modules   string `json:"modules"` // El servidor envía los módulos como una cadena JSON
}

// NetworkError se usa para distinguir fallos de conexión de rechazos del servidor.
type NetworkError struct {
	msg string
}

func (e *NetworkError) Error() string {
	return e.msg
}

// --- FUNCIONES DE UTILIDAD INTERNAS (PRIVADAS) ---

// getMachineID genera y retorna un ID de máquina único, usando el AppID de la configuración.
func (mgr *LicenseManager) getMachineID() (string, error) {
	return machineid.ProtectedID(mgr.Config.AppID)
}

// encrypt cifra los datos con AES-GCM.
func encrypt(plaintext []byte, key []byte) ([]byte, error) {
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

// decrypt descifra los datos con AES-GCM.
func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
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
		return nil, fmt.Errorf("texto cifrado demasiado corto")
	}

	nonce, encryptedData := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// saveLicenseData cifra y guarda la clave, el token, los módulos y la expiración en un archivo local.
func (mgr *LicenseManager) saveLicenseData() error {
	dataToSave := EncryptedLicenseData{
		Token:          mgr.CurrentToken,
		LicenseKey:     mgr.LicenseKey,
		ExpiresAt:      mgr.ExpiresAt,
		AllowedModules: mgr.AllowedModules,
	}

	jsonData, err := json.Marshal(dataToSave)
	if err != nil {
		return fmt.Errorf("error al serializar JSON: %w", err)
	}

	encryptedBytes, err := encrypt(jsonData, mgr.Config.EncryptionKey)
	if err != nil {
		return fmt.Errorf("error al cifrar datos: %w", err)
	}

	encodedData := base64.StdEncoding.EncodeToString(encryptedBytes)

	err = os.WriteFile(StorageFile, []byte(encodedData), 0600)
	if err != nil {
		return fmt.Errorf("error al escribir archivo de licencia: %w", err)
	}

	log.Println("🔑 Datos de licencia cifrados y guardados en", StorageFile)
	return nil
}

// loadLicenseData carga y descifra la clave, el token, los módulos y la expiración desde el archivo local.
func (mgr *LicenseManager) loadLicenseData() error {
	content, err := os.ReadFile(StorageFile)
	if err != nil {
		return fmt.Errorf("archivo de licencia no encontrado o inaccesible: %w", err)
	}

	encryptedBytes, err := base64.StdEncoding.DecodeString(string(content))
	if err != nil {
		return fmt.Errorf("error al decodificar Base64: %w", err)
	}

	decryptedBytes, err := decrypt(encryptedBytes, mgr.Config.EncryptionKey)
	if err != nil {
		return fmt.Errorf("error al descifrar datos (clave o archivo corrupto): %w", err)
	}

	var loadedData EncryptedLicenseData
	if err := json.Unmarshal(decryptedBytes, &loadedData); err != nil {
		return fmt.Errorf("error al deserializar JSON: %w", err)
	}

	// Cargar los datos en el manager
	mgr.CurrentToken = loadedData.Token
	mgr.LicenseKey = loadedData.LicenseKey
	mgr.ExpiresAt = loadedData.ExpiresAt
	mgr.AllowedModules = loadedData.AllowedModules

	log.Println("🔑 Datos de licencia cargados con éxito desde", StorageFile)
	return nil
}

// parseAndSetModules toma la respuesta del servidor y actualiza los módulos del manager.
func (mgr *LicenseManager) parseAndSetModules(modulesJSON string) {
	var modules []string
	if err := json.Unmarshal([]byte(modulesJSON), &modules); err != nil {
		log.Printf("Advertencia: Falló la deserialización de módulos JSON: %v", err)
		mgr.AllowedModules = []string{"error"} // Default
	} else {
		mgr.AllowedModules = modules
	}
}

// parseAndSetExpiration toma la respuesta del servidor y actualiza la fecha de expiración.
func (mgr *LicenseManager) parseAndSetExpiration(expiresAtStr string) {
	t, err := time.Parse(time.RFC3339, expiresAtStr)
	if err != nil {
		log.Printf("Advertencia: Falló el parseo de la fecha de expiración: %v", err)
		mgr.ExpiresAt = time.Time{}
	} else {
		mgr.ExpiresAt = t
	}
}

// validateToken realiza el chequeo periódico (Heartbeat) con el servidor.
func (mgr *LicenseManager) validateToken() error {
	log.Println("--- INICIANDO CHECK-IN DE LICENCIA ---")

	if mgr.CurrentToken == "" {
		mgr.IsValid = false
		return fmt.Errorf("no hay token guardado. Fallo del sistema de persistencia")
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
		// Retorna NetworkError para activar el período de gracia
		return &NetworkError{msg: fmt.Sprintf("error de red al validar: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		mgr.IsValid = false
		var errorMsg bytes.Buffer
		errorMsg.ReadFrom(resp.Body)
		// Retorna error de servidor (no se aplica período de gracia)
		return fmt.Errorf("validación fallida (HTTP %d): %s", resp.StatusCode, errorMsg.String())
	}

	var response ClientLicenseResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		mgr.IsValid = false
		return fmt.Errorf("error al decodificar la respuesta de validación: %w", err)
	}

	// El servidor responde OK: SU ESTADO PREVALECE, actualizamos la expiración y validamos.
	mgr.parseAndSetExpiration(response.ExpiresAt)
	mgr.parseAndSetModules(response.Modules)

	mgr.CurrentToken = response.Token
	mgr.IsValid = true
	log.Println("✅ Check-in exitoso. Token renovado. Continuar uso.")

	// Guardar el nuevo token, clave, expiración y módulos cifrados
	if err := mgr.saveLicenseData(); err != nil {
		log.Printf("Advertencia: No se pudo guardar el archivo de licencia cifrado después de la renovación: %v", err)
	}
	return nil
}

// startValidationLoop inicia el chequeo periódico de licencia en segundo plano.
func (mgr *LicenseManager) startValidationLoop() {
	ticker := time.NewTicker(mgr.Config.ValidationInterval)
	defer ticker.Stop()

	for range ticker.C {
		err := mgr.validateToken()
		if err != nil {
			log.Printf("⛔ ERROR DE LICENCIA PERIÓDICO: %v", err)
			mgr.IsValid = false

			if _, isNetError := err.(*NetworkError); isNetError {
				// LÓGICA DEL PERÍODO DE GRACIA EN SEGUNDO PLANO
				if time.Now().Before(mgr.ExpiresAt) {
					log.Println("⚠️ Manteniendo activo con período de gracia (FALLO DE RED).")
					mgr.IsValid = true
				} else {
					log.Println("🚨 PERÍODO DE GRACIA EXPIRADO. Bloqueando funcionalidad.")
					mgr.IsValid = false
				}
			} else {
				// El error NO es de red, sino de RECHAZO DEL SERVIDOR (bloqueo inmediato)
				log.Println("🚨 RECHAZO DEL SERVIDOR. Bloqueando funcionalidad inmediatamente.")
				mgr.IsValid = false
			}
		}
	}
}

// --- MÉTODOS EXPORTADOS PARA EL CONSUMIDOR ---

// NewManager crea e inicializa una nueva instancia de LicenseManager.
func NewManager(cfg Config) (*LicenseManager, error) {
	mgr := &LicenseManager{
		Config: cfg,
	}

	// 1. Obtener Machine ID
	var err error
	mgr.MachineID, err = mgr.getMachineID()
	if err != nil {
		return nil, fmt.Errorf("error al obtener Machine ID: %w", err)
	}

	// 2. Intentar cargar datos guardados
	loadErr := mgr.loadLicenseData()
	if loadErr != nil {
		log.Printf("INFO: No se pudo cargar la licencia cifrada. Se requiere activación inicial: %v", loadErr)
		// Dejar mgr.CurrentToken vacío, lo que fuerza la activación
	} else {
		// 3. Si cargó, intentar la validación inicial (heartbeat)
		log.Println("Licencia cargada. Intentando validar token...")
		validationErr := mgr.validateToken()

		if validationErr != nil {
			log.Printf("⛔ VALIDACIÓN FALLIDA: %v", validationErr)

			if _, isNetError := validationErr.(*NetworkError); isNetError {
				// Período de gracia si hay error de red
				if time.Now().Before(mgr.ExpiresAt) {
					mgr.IsValid = true
					log.Println("⚠️ Usando período de gracia local (FALLO DE RED).")
				} else {
					return nil, fmt.Errorf("token expirado localmente y fallo de conexión: la aplicación no puede iniciar")
				}
			} else {
				// Rechazo del servidor (bloqueo total)
				return nil, fmt.Errorf("rechazo de validación por el servidor: %w", validationErr)
			}
		}
	}

	// 4. Iniciar el chequeo periódico en segundo plano
	go mgr.startValidationLoop()

	return mgr, nil
}

// Activate intenta la activación inicial o reactivación con una clave de licencia.
// Se usa si NewManager falla o si el token está vacío.
func (mgr *LicenseManager) Activate(licenseKey string) error {
	mgr.LicenseKey = licenseKey

	reqBody := ClientLicenseRequest{LicenseKey: mgr.LicenseKey, MachineID: mgr.MachineID}
	jsonBody, _ := json.Marshal(reqBody)

	resp, err := http.Post(mgr.Config.ApiActivateURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("error de conexión con el servidor de licencias: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorMsg bytes.Buffer
		errorMsg.ReadFrom(resp.Body)
		return fmt.Errorf("activación fallida (HTTP %d): %s", resp.StatusCode, errorMsg.String())
	}

	var response ClientLicenseResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("error al decodificar respuesta de activación: %w", err)
	}

	mgr.parseAndSetExpiration(response.ExpiresAt)
	mgr.parseAndSetModules(response.Modules)

	mgr.CurrentToken = response.Token
	mgr.IsValid = true
	log.Println("✅ Licencia activada con éxito. Token obtenido y módulos actualizados.")

	// Guardar la licencia recién activada
	if err := mgr.saveLicenseData(); err != nil {
		log.Printf("Advertencia: No se pudo guardar el archivo de licencia cifrado: %v", err)
	}
	return nil
}

// CheckModule es la función clave que el consumidor usará para verificar permisos.
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

// GetStatus retorna si la licencia es válida o no.
func (mgr *LicenseManager) GetStatus() bool {
	return mgr.IsValid
}

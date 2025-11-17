# 🔑 Licensing Client Go3t

Este repositorio contiene una librería cliente para la gestión de licencias de aplicaciones escritas en Go3T. El cliente maneja la activación inicial (generación de license.dat), la validación periódica (heartbeat) con un servidor de licencias externo, el almacenamiento seguro (cifrado AES-GCM) de tokens y el chequeo de módulos.

## 📦 Estructura del Proyecto

El proyecto se divide en dos partes principales:

licensingclient (Librería): Contiene toda la lógica de gestión de licencias, cifrado, almacenamiento y comunicación con el servidor.

main.go (Aplicación de Demostración): Muestra cómo integrar la librería para forzar la activación inicial y controlar el flujo de la aplicación basado en el estado de la licencia.

## 🛠️ Instalación y Dependencias

```go 
go mod tidy
go mod vendor
```


## 💻 Uso de Demostración

El siguiente código (main.go) demuestra el flujo de trabajo esencial:

Intenta inicializar el manager (cargando license.dat y validando).

Si el manager falla al cargar o validar (porque license.dat no existe), fuerza el modo de Activación pidiendo una clave al usuario.

Si la activación o la carga inicial son exitosas, inicia el bucle principal de la aplicación.

Mantiene una validación periódica en segundo plano.

Nota: Para que este código funcione en el primer arranque, debe haber un servidor de licencias ejecutándose en *http://localhost:8080* que responda a las rutas **/api/v1/activate** y **/api/v1/validate**.

> main.go
```go
package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/platformgo3t/seallify/licensingclient"
)

// Constantes de API
const API_ACTIVATE_URL = "http://localhost:8080/api/v1/activate"
const API_VALIDATE_URL = "http://localhost:8080/api/v1/validate"
const ValidationInterval = 1 * time.Minute

// Clave de 32 bytes para AES-256 (CRÍTICA: Debe ser secreta y única por aplicación)
var EncryptionKey = []byte("clave-secreta-de-32-bytes-aesgcm")

const AppID = "MiNombreDeAplicacionConLicencia"

func main() {
	// Configurar logs para incluir fecha, hora y archivo para mejor seguimiento.
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	config := licensingclient.Config{
		ApiActivateURL:     API_ACTIVATE_URL,
		ApiValidateURL:     API_VALIDATE_URL,
		EncryptionKey:      EncryptionKey,
		ValidationInterval: ValidationInterval,
		AppID:              AppID,
	}

	// 1. Crear e inicializar el LicenseManager (Intenta cargar y validar en background)
	mgr, err := licensingclient.NewManager(config)

	// Si NewManager falló, significa que no se pudo cargar el archivo,
	// O la revalidación falló por rechazo/expiración.
	if err != nil {
		log.Printf("⛔ FALLO DE INICIALIZACIÓN: %v", err)
	}

	// Si el token sigue vacío después de la inicialización (caso de licencia.dat faltante)
	// o si el manager es nulo (caso de MachineID fail), forzamos la activación.
	// La comprobación !mgr.GetStatus() evita que el bucle principal se ejecute
    // si el servidor rechazó el token existente.
	if mgr == nil || mgr.CurrentToken == "" || !mgr.GetStatus() {

		// Asegurarse de tener un manager si NewManager falló por alguna razón
		if mgr == nil {
			// Intentar crear un manager básico para la activación si falló MachineID
			mgr, _ = licensingclient.NewManager(config)
			if mgr == nil {
				log.Fatal("ERROR CRÍTICO: No se pudo crear el manager, incluso para activación.")
			}
		}

		fmt.Print("=========================================\n")
		fmt.Print("  LICENCIA DE LA APLICACIÓN\n")
		fmt.Print("=========================================\n")
		fmt.Print("Por favor, ingrese su Clave de Licencia (Ej: MI-APP-LIC-12345): ")

		var licenseKey string
		// Usamos Scanf para asegurar que lee la línea completa
		_, scanErr := fmt.Scanf("%s", &licenseKey)
		if scanErr != nil {
			log.Fatal("Error al leer la clave. Abortando: ", scanErr)
		}

		// Intento de Activación completa (obtiene el primer token y módulos)
		if activateErr := mgr.Activate(licenseKey); activateErr != nil {
			log.Printf("⛔ ERROR CRÍTICO: La aplicación no puede iniciar.")
			fmt.Printf("\nMotivo del Fallo en Activación: %v\n", activateErr)
			os.Exit(1)
		}
	}

	// Si la licencia es inválida en este punto (ya sea por NewManager o Activate),
	// significa que fue un rechazo de servidor y salimos.
	if !mgr.GetStatus() {
		log.Printf("⛔ ERROR CRÍTICO: La validación o activación inicial fue rechazada por el servidor.")
		os.Exit(1)
	}

	// 4. BUCLE PRINCIPAL DE LA APLICACIÓN (Solo se llega aquí si GetStatus() es true)
	fmt.Printf("\n¡APLICACIÓN INICIADA! (Validando cada %s)\n", ValidationInterval)

	for {
		if mgr.GetStatus() {
			fmt.Printf("...[LÓGICA PRINCIPAL]... Licencia válida (Expira: %s). Módulos activos: %s\n", mgr.ExpiresAt.Format("2006-01-02 15:04:05"), strings.Join(mgr.AllowedModules, ", "))
			// Ejemplo de chequeo de módulos
			if mgr.CheckModule("premium") {
				fmt.Println(">>> Módulo 'premium' activo. Acceso total.")
			} else {
				fmt.Println(">>> Módulo 'premium' inactivo.")
			}
		} else {
			fmt.Printf("!!! [BLOQUEADO] !!! Licencia Inválida/Revocada. Funcionalidad limitada.\n")
		}
		time.Sleep(5 * time.Second)
	}
}
```
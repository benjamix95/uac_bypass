# UAC Bypass Tool (Scopo Educativo)

## ⚠️ Avvertenza
Questo progetto è sviluppato **esclusivamente per scopi educativi** per comprendere i meccanismi di sicurezza di Windows UAC. Non utilizzare in ambienti di produzione o per scopi malevoli.

## 📋 Requisiti
- Windows 10 o superiore
- Visual Studio 2019/2022 o CMake 3.10+
- UAC abilitato nel sistema
- Utente membro del gruppo Administrators
- **Nota**: Il tool deve essere eseguito SENZA privilegi elevati (non tramite "Esegui come amministratore")

## ⚡ Come Funziona
È fondamentale comprendere che:

1. **Requisiti di Base**:
   - Il bypass UAC funziona SOLO per utenti che sono già nel gruppo Administrators
   - L'UAC è un meccanismo di "protezione" per gli amministratori, non per utenti standard
   - I metodi di bypass (fodhelper.exe, wsreset.exe, etc.) richiedono che l'utente sia nel gruppo Administrators

2. **Design dell'UAC**:
   - L'UAC è progettato per proteggere gli amministratori da esecuzioni non autorizzate
   - Un utente standard non può ottenere privilegi amministrativi tramite UAC bypass
   - Gli utenti standard devono usare "Run as Administrator" e fornire credenziali di un account amministratore

3. **Importante**:
   - Il bypass UAC non è un modo per "ottenere" privilegi amministrativi
   - È un metodo per evitare il prompt di conferma UAC per un utente che è già amministratore
   - Non può elevare i privilegi di un utente standard

## 🛠️ Compilazione

### Usando CMake
```bash
# Crea directory build
mkdir build
cd build

# Configura il progetto
cmake ..

# Compila
cmake --build . --config Release
```

### Usando Visual Studio
1. Aprire il progetto in Visual Studio
2. Selezionare la configurazione Release
3. Compilare il progetto (F7)

## 📦 Struttura Progetto
```
uac_bypass/
├── src/                    # Codice sorgente
│   ├── UAC_Bypass.cpp     # Entry point
│   ├── Logger.cpp         # Sistema di logging
│   └── ProcessElevator.cpp# Logica elevazione
├── include/               # Header files
│   ├── Config.h          # Configurazioni
│   ├── Logger.h          # Definizioni logger
│   └── ProcessElevator.h # Definizioni elevazione
├── docs/                 # Documentazione
├── tests/                # Unit tests
└── tools/                # Utility
```

## 🚀 Utilizzo
```bash
# Esegui il programma SENZA privilegi amministrativi (non usare "Esegui come amministratore")
.\bin\Release\uac_bypass.exe

# Il programma:
# 1. Verifica di essere in esecuzione senza privilegi elevati
# 2. Controlla l'appartenenza al gruppo Administrators
# 3. Utilizza tecniche di bypass per ottenere privilegi elevati
# 4. Mostra il risultato dell'elevazione
```

## 📝 Note di Sicurezza
1. Il tool effettua modifiche temporanee al registro di sistema
2. Tutte le operazioni vengono registrate in un file di log
3. Il tool implementa meccanismi di ripristino automatico
4. Utilizzare solo in ambiente di test isolato

## 🔍 Funzionalità
- Elevazione privilegi per utenti standard:
  * Token stealing da processi privilegiati
  * Exploitation servizi vulnerabili
  * Manipolazione token di sistema
  * Bypass controlli integrità
  * Recovery automatico
- Bypass UAC tramite tecniche multiple
- Sistema di comunicazione ibrido:
  - Shared memory con cifratura AES
  - Fallback automatico a named pipes
  - Sincronizzazione avanzata tra processi
  - Performance ottimizzate
  - Protezione memoria condivisa
- Sistema di logging avanzato con tracciamento dettagliato
- Gestione automatica del cleanup con ripristino garantito
- Controlli di sicurezza estesi:
  - Verifica firma digitale dei processi target
  - Validazione integrità file eseguibili
  - Protezione accesso al registro di sistema
  - Gestione sicura delle risorse COM
  - Cifratura end-to-end dei dati
- Sistema di backup e ripristino automatico del registro
- Gestione timeout e recovery automatico
- Protezione contro manipolazioni malevole
- Recovery automatico in caso di errori di comunicazione

## 📚 Documentazione
- [Dettagli Tecnici](docs/technical_details.md)
- [Note di Sicurezza](docs/security_notes.md)

## 🔄 Changelog

### [0.3.0] - 2025-01-27
#### Aggiunto
- Implementazione COM elevation con moniker
- Sistema di protezione DLL e verifica firma
- Detection evasion avanzato
- Unit testing con Google Test
- SecurityUtils per gestione sicurezza
- Anti-debug e anti-VM protection
- Process hollowing e thread manipulation
- Memory protection e encryption
- Sistema di verifica integrità
- Payload DLL per elevazione privilegi
- Comunicazione sicura via pipe
- Nuovi metodi di bypass (computerdefaults.exe, sdclt.exe, eventvwr.exe)
- Sistema di gestione bypass modulare

#### Sicurezza
- Sistema di protezione memoria
- Controlli anti-debugging avanzati
- Evasione da sandbox
- Protezione contro memory dumping
- Cifratura regioni memoria sensibili
- Sistema rilevamento VM completo
- Tecniche di evasione VM avanzate

#### Tecnico
- Ottimizzazione gestione COM
- Sistema di logging avanzato
- Controlli integrità runtime
- Virtualizzazione codice completa
- Sandboxing avanzato
- Test di fuzzing e stress
- Virtualizzazione hardware con VT-x/AMD-V
- Token stealing avanzato
- Named pipe impersonation
- RPC elevation sicura
- Service manipulation avanzata
- Sistema gestione errori completo

### [0.2.0] - 2024-09-14
#### Sicurezza
- Verifica firma digitale processi
- Gestione sicura registro
- Verifica integrità file
- Sicurezza risorse COM
- Controlli sicurezza registro

#### Correzioni
- Risolto problema IsProcessElevated
- Corretto uso percorsi System32
- Aggiunto timeout thread remoti
- Verifica codici uscita processi

#### Miglioramenti
- Backup/ripristino registro completo
- Gestione registro avanzata
- Logging dettagliato
- Ottimizzazione risorse
- Pulizia automatica file temporanei

### [0.1.0] - 2024-04-05
#### Iniziale
- Prima release del progetto
- Bypass UAC base
- Sistema logging base
- Gestione processi base
- Elevazione privilegi base

## ⚖️ Licenza
Questo progetto è rilasciato per scopi educativi. Non è consentito l'uso in produzione o per scopi malevoli.

## 🤝 Contribuire
Questo è un progetto educativo. I contributi devono:
1. Mantenere il focus educativo
2. Implementare controlli di sicurezza appropriati
3. Fornire documentazione dettagliata
4. Seguire le best practice di codifica

## ⚠️ Disclaimer
L'autore non è responsabile per l'uso improprio di questo software. Questo tool è stato sviluppato esclusivamente per scopi educativi e di ricerca sulla sicurezza.

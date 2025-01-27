# Changelog
Tutte le modifiche significative al progetto saranno documentate in questo file.

Il formato è basato su [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
e questo progetto aderisce al [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2025-01-27
### Aggiunto
- Implementazione completa COM elevation con moniker
- Sistema avanzato di protezione DLL e verifica firma
- Funzionalità di detection evasion
- Unit testing completo con Google Test
- Classe SecurityUtils per gestione sicurezza avanzata
- Anti-debug e anti-VM checks
- Process hollowing e thread manipulation
- Memory protection e encryption
- Sistema di verifica integrità avanzato
- Payload DLL per elevazione privilegi
- Test unitari per il payload DLL
- Sistema di comunicazione via pipe
- Verifica integrità runtime
- Metodi di bypass alternativi (computerdefaults.exe, sdclt.exe, eventvwr.exe)
- Sistema di gestione bypass modulare con backup automatico

### Sicurezza
- Implementato sistema di protezione memoria
- Aggiunti controlli anti-debugging avanzati
- Implementata evasione da sandbox
- Migliorata protezione contro memory dumping
- Aggiunta cifratura delle regioni di memoria sensibili
- Sistema avanzato di rilevamento VM:
  * Detection di VMware, VirtualBox, Hyper-V, QEMU, Xen, Parallels
  * Analisi hardware (CPUID, MSR, TSC, IDT/LDT/GDT)
  * Controlli su processi, servizi e driver
  * Verifica timing e comportamento
- Tecniche di evasione VM:
  * Modifica timing e comportamento
  * Spoofing hardware
  * Nascondimento processi
  * Simulazione ambiente reale

### Tecnico
- Ottimizzazione gestione COM con namespace dedicato
- Miglioramento sistema di logging per eventi di sicurezza
- Implementazione controlli di integrità runtime
- Aggiunta protezione contro analisi dinamica
- Sistema di virtualizzazione del codice:
  * Traduzione codice nativo in bytecode virtuale
  * VM personalizzata per esecuzione codice
  * Protezione contro reverse engineering
  * Offuscamento istruzioni e flusso di controllo
  * Emulazione chiamate API
- Sistema avanzato di sandboxing:
  * Isolamento completo dell'esecuzione
  * Policy di sicurezza configurabili
  * Restrizioni filesystem e registro
  * Controllo accessi granulare
  * Monitoraggio attività runtime
- Test avanzati:
  * Test di fuzzing per tutti i componenti
  * Test di stress con operazioni concorrenti
  * Fuzzing input e parametri
  * Test di robustezza e resilienza
  * Verifica gestione errori
- Virtualizzazione hardware:
  * Supporto VT-x/AMD-V
  * Emulazione CPU completa
  * Extended Page Tables (EPT)
  * Gestione VM exits
  * Protezione memoria hardware
  * Intercettazione MSR/IO
- Tecniche avanzate di bypass:
  * Token stealing da processi privilegiati
  * Manipolazione token e privilegi
  * Impersonazione token SYSTEM
  * Protezione token rubati
  * Monitoraggio utilizzo token
  * Named pipe impersonation
  * Comunicazione sicura via pipe
  * Elevazione tramite pipe
  * Protezione accessi pipe
  * Gestione client pipe
  * RPC elevation
  * Autenticazione RPC sicura
  * Binding RPC protetto
  * Impersonazione RPC
  * Gestione endpoint RPC
  * Service manipulation
  * Hijacking servizi Windows
  * Modifica binari servizi
  * Iniezione in servizi
  * Gestione privilegi servizi
  * Sistema gestione errori avanzato
  * Recovery automatico errori
  * Analisi pattern errori
  * Logging errori dettagliato
  * Gestione errori distribuita

## [0.2.0] - 2025-01-27
### Sicurezza
- Aggiunta verifica della firma digitale per i processi target
- Implementata gestione sicura del backup e ripristino del registro
- Aggiunta verifica dell'integrità dei file eseguibili
- Migliorata la sicurezza nella gestione delle risorse COM
- Implementati controlli di sicurezza aggiuntivi nella manipolazione del registro

### Correzioni
- Risolto problema di accessibilità della funzione IsProcessElevated
- Corretto l'uso di percorsi hardcoded per System32
- Aggiunto timeout nell'attesa dei thread remoti
- Implementata verifica dei codici di uscita dei processi

### Miglioramenti
- Implementata gestione completa del backup e ripristino del registro
- Aggiunta logica completa per la manipolazione del registro
- Migliorato il sistema di logging con messaggi più dettagliati
- Ottimizzata la gestione delle risorse di sistema
- Implementata pulizia automatica dei file temporanei

### Tecnico
- Aggiunta corretta chiusura delle handle di sistema
- Implementata gestione degli errori più robusta
- Migliorata la gestione della memoria
- Ottimizzata la gestione delle risorse COM

## [0.1.0] - 2025-01-27
### Iniziale
- Prima release del progetto
- Implementazione base del bypass UAC
- Sistema di logging base
- Gestione base dei processi
- Funzionalità di base per l'elevazione dei privilegi
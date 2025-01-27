#include "../include/Encryption.h"
#include <wincrypt.h>
#pragma comment(lib, "advapi32")

namespace uac_bypass {

Encryption::Encryption()
    : logger(Logger::getInstance()),
      hProvider(NULL),
      hKey(NULL),
      initialized(false) {
}

Encryption::~Encryption() {
    cleanup();
}

Encryption& Encryption::getInstance() {
    static Encryption instance;
    return instance;
}

bool Encryption::initialize() {
    if (initialized) return true;
    
    if (!initializeAES()) {
        cleanup();
        return false;
    }
    
    initialized = true;
    return true;
}

void Encryption::cleanup() {
    cleanupAES();
    initialized = false;
}

bool Encryption::encryptData(const BYTE* input, DWORD inputSize,
                           BYTE* output, DWORD& outputSize) {
    if (!initialized || !input || !output) return false;
    
    // Copia input in output per crittografia in-place
    memcpy(output, input, inputSize);
    outputSize = inputSize;
    
    // Cripta i dati
    if (!CryptEncrypt(hKey, NULL, TRUE, 0, output, &outputSize, outputSize)) {
        logger.logError(L"Crittografia dati fallita");
        return false;
    }
    
    return true;
}

bool Encryption::decryptData(const BYTE* input, DWORD inputSize,
                           BYTE* output, DWORD& outputSize) {
    if (!initialized || !input || !output) return false;
    
    // Copia input in output per decrittografia in-place
    memcpy(output, input, inputSize);
    outputSize = inputSize;
    
    // Decripta i dati
    if (!CryptDecrypt(hKey, NULL, TRUE, 0, output, &outputSize)) {
        logger.logError(L"Decrittografia dati fallita");
        return false;
    }
    
    return true;
}

bool Encryption::generateKey() {
    if (!initialized) return false;
    
    // Genera chiave casuale
    keyData.resize(KEY_SIZE);
    if (!CryptGenRandom(hProvider, KEY_SIZE, keyData.data())) {
        logger.logError(L"Generazione chiave fallita");
        return false;
    }
    
    return setKey(keyData.data(), KEY_SIZE);
}

bool Encryption::setKey(const BYTE* key, DWORD keySize) {
    if (!initialized || !key || keySize != KEY_SIZE) return false;
    
    // Distruggi chiave esistente
    if (hKey) {
        CryptDestroyKey(hKey);
        hKey = NULL;
    }
    
    // Struttura per importazione chiave
    struct {
        BLOBHEADER header;
        DWORD keySize;
        BYTE keyData[KEY_SIZE];
    } keyBlob;
    
    // Prepara blob chiave
    keyBlob.header.bType = PLAINTEXTKEYBLOB;
    keyBlob.header.bVersion = CUR_BLOB_VERSION;
    keyBlob.header.reserved = 0;
    keyBlob.header.aiKeyAlg = CALG_AES_256;
    keyBlob.keySize = KEY_SIZE;
    memcpy(keyBlob.keyData, key, KEY_SIZE);
    
    // Importa chiave
    if (!CryptImportKey(hProvider,
        (BYTE*)&keyBlob, sizeof(keyBlob),
        NULL, CRYPT_EXPORTABLE, &hKey)) {
        logger.logError(L"Importazione chiave fallita");
        return false;
    }
    
    // Salva copia chiave
    keyData.assign(key, key + keySize);
    
    return true;
}

bool Encryption::initializeAES() {
    // Acquisici contesto crittografico
    if (!CryptAcquireContextW(&hProvider,
        NULL, MS_ENH_RSA_AES_PROV_W,
        PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        logger.logError(L"Acquisizione contesto crittografico fallita");
        return false;
    }
    
    return true;
}

void Encryption::cleanupAES() {
    if (hKey) {
        CryptDestroyKey(hKey);
        hKey = NULL;
    }
    
    if (hProvider) {
        CryptReleaseContext(hProvider, 0);
        hProvider = NULL;
    }
    
    keyData.clear();
}

} // namespace uac_bypass

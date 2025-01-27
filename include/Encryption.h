#ifndef UAC_BYPASS_ENCRYPTION_H
#define UAC_BYPASS_ENCRYPTION_H

#include <windows.h>
#include <vector>
#include <string>
#include "Logger.h"

namespace uac_bypass {

class Encryption {
public:
    static Encryption& getInstance();
    
    bool initialize();
    void cleanup();
    
    bool encryptData(const BYTE* input, DWORD inputSize, 
                     BYTE* output, DWORD& outputSize);
    bool decryptData(const BYTE* input, DWORD inputSize,
                     BYTE* output, DWORD& outputSize);
    
    bool generateKey();
    bool setKey(const BYTE* key, DWORD keySize);
    
private:
    Encryption();
    ~Encryption();
    
    Encryption(const Encryption&) = delete;
    Encryption& operator=(const Encryption&) = delete;
    
    bool initializeAES();
    void cleanupAES();
    
    HCRYPTPROV hProvider;
    HCRYPTKEY hKey;
    Logger& logger;
    bool initialized;
    
    static const DWORD KEY_SIZE = 32; // 256 bit
    static const DWORD BLOCK_SIZE = 16;
    std::vector<BYTE> keyData;
};

} // namespace uac_bypass

#endif // UAC_BYPASS_ENCRYPTION_H

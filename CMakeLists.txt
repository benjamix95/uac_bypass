hacmake_minimum_required(VERSION 3.10)
project(uac_bypass VERSION 0.3.0 LANGUAGES CXX)

# Impostazioni di compilazione
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Opzioni di compilazione
if(MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

# Opzione per abilitare i test
option(BUILD_TESTING "Build the testing tree." ON)

# Include FetchContent per scaricare le dipendenze
include(FetchContent)

# Scarica e configura Google Test
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG release-1.12.1
)
FetchContent_MakeAvailable(googletest)

# File sorgenti principali
# Trova libreria distorm
find_library(DISTORM_LIBRARY
    NAMES distorm3
    PATHS ${CMAKE_SOURCE_DIR}/lib
)

if(NOT DISTORM_LIBRARY)
    message(FATAL_ERROR "distorm library not found")
endif()

include_directories(${CMAKE_SOURCE_DIR}/include/distorm)

set(SOURCES
    src/UAC_Bypass.cpp
    src/Logger.cpp
    src/ProcessElevator.cpp
    src/ComManager.cpp
    src/SecurityUtils.cpp
    src/ObfuscationUtils.cpp
    src/BypassMethods.cpp
    src/VMDetection.cpp
    src/CodeVirtualization.cpp
    src/Sandboxing.cpp
    src/HardwareVirtualization.cpp
    src/TokenStealing.cpp
    src/NamedPipeImpersonation.cpp
    src/RPCElevation.cpp
    src/ServiceManipulation.cpp
    src/ErrorHandler.cpp
)

# File header
set(HEADERS
    include/Config.h
    include/Logger.h
    include/ProcessElevator.h
    include/ComManager.h
    include/ComInterfaces.h
    include/SecurityUtils.h
    include/ObfuscationUtils.h
    include/BypassMethods.h
    include/VMDetection.h
    include/CodeVirtualization.h
    include/Sandboxing.h
    include/HardwareVirtualization.h
    include/VMXDefs.h
    include/TokenStealing.h
    include/NamedPipeImpersonation.h
    include/RPCElevation.h
    include/ServiceManipulation.h
    include/ErrorHandler.h
)

# Payload DLL
set(PAYLOAD_SOURCES
    src/PayloadDLL.cpp
)

set(PAYLOAD_HEADERS
    include/PayloadDLL.h
)

# Aggiungi la DLL
add_library(payload_dll SHARED
    ${PAYLOAD_SOURCES}
    ${PAYLOAD_HEADERS}
)

# Directory di inclusione per la DLL
target_include_directories(payload_dll PRIVATE include)

# Librerie per la DLL

# Test configuration
enable_testing()
include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG release-1.12.1
)
FetchContent_MakeAvailable(googletest)

# Test executable
add_executable(unit_tests
    tests/UnitTests.cpp
    tests/PayloadTests.cpp
    tests/FuzzingTests.cpp
    tests/ErrorHandlerTests.cpp
)

target_link_libraries(unit_tests PRIVATE
    gtest
    gtest_main
    payload_dll
)

include(GoogleTest)
gtest_discover_tests(unit_tests)
target_link_libraries(payload_dll PRIVATE
    advapi32
    shell32
    ole32
    oleaut32
    ntdll
    crypt32
    userenv
    wintrust
)

# Definizioni per la DLL
target_compile_definitions(payload_dll PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

# Output directory per la DLL
set_target_properties(payload_dll PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    OUTPUT_NAME "payload"
)

# Eseguibile principale
add_executable(uac_bypass ${SOURCES} ${HEADERS})

# Directory di inclusione
target_include_directories(uac_bypass PRIVATE include)

# Librerie Windows necessarie
target_link_libraries(uac_bypass PRIVATE
    advapi32  # Per funzioni registro e token
    shell32   # Per funzioni shell
    ole32     # Per COM
    oleaut32  # Per COM automation
    ntdll     # Per funzioni NT
    crypt32   # Per funzioni di crittografia
    dbghelp   # Per manipolazione simboli debug
    iphlpapi  # Per funzioni di rete
    psapi     # Per funzioni di processo
    ${DISTORM_LIBRARY}  # Per disassembly e analisi codice
)

# Definizioni di compilazione
target_compile_definitions(uac_bypass PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

# Impostazioni specifiche per Windows
if(WIN32)
    # Richiedi privilegi amministrativi nel manifest
    set_target_properties(uac_bypass PROPERTIES
        LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\"")
endif()

# Output directory
set_target_properties(uac_bypass PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# Configurazione dei test
if(BUILD_TESTING)
    enable_testing()
    
    # Test principali
    add_executable(uac_bypass_tests
        tests/UnitTests.cpp
        src/Logger.cpp
        src/ProcessElevator.cpp
        src/ComManager.cpp
        src/SecurityUtils.cpp
        src/ObfuscationUtils.cpp
    )
    
    # Test del payload
    add_executable(payload_tests
        tests/PayloadTests.cpp
        src/PayloadDLL.cpp
        src/Logger.cpp
    )

    # Test di fuzzing
    add_executable(fuzzing_tests
        tests/FuzzingTests.cpp
        src/Logger.cpp
        src/ProcessElevator.cpp
        src/ComManager.cpp
        src/SecurityUtils.cpp
        src/ObfuscationUtils.cpp
        src/BypassMethods.cpp
        src/VMDetection.cpp
        src/CodeVirtualization.cpp
        src/Sandboxing.cpp
    )
    
    # Collega librerie per test principali
    target_link_libraries(uac_bypass_tests PRIVATE
        gtest
        gtest_main
        advapi32
        shell32
        ole32
        oleaut32
        ntdll
        crypt32
        dbghelp
    )
    
    # Collega librerie per test payload
    target_link_libraries(payload_tests PRIVATE
        gtest
        gtest_main
        advapi32
        shell32
    )

    # Collega librerie per test di fuzzing
    target_link_libraries(fuzzing_tests PRIVATE
        gtest
        gtest_main
        advapi32
        shell32
        ole32
        oleaut32
        ntdll
        crypt32
        dbghelp
        iphlpapi
        psapi
        ${DISTORM_LIBRARY}
    )

    target_include_directories(fuzzing_tests PRIVATE
        include
        ${gtest_SOURCE_DIR}/include
    )

    # Aggiungi test a CTest
    add_test(NAME fuzzing_tests COMMAND fuzzing_tests)

    # Output directory per test di fuzzing
    set_target_properties(fuzzing_tests PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
        ole32
        oleaut32
        ntdll
        crypt32
        userenv
        wintrust
    )
    
    # Directory di inclusione per i test
    target_include_directories(uac_bypass_tests PRIVATE
        include
        ${gtest_SOURCE_DIR}/include
    )
    
    target_include_directories(payload_tests PRIVATE
        include
        ${gtest_SOURCE_DIR}/include
    )
    
    # Aggiungi i test a CTest
    add_test(NAME uac_bypass_tests COMMAND uac_bypass_tests)
    add_test(NAME payload_tests COMMAND payload_tests)
    
    # Output directory per i test
    set_target_properties(uac_bypass_tests PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    
    set_target_properties(payload_tests PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    
    # Definizioni di compilazione per i test
    target_compile_definitions(uac_bypass_tests PRIVATE
        UNICODE
        _UNICODE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        TESTING
    )
    
    # Aggiungi il test al CTest
    add_test(NAME uac_bypass_tests COMMAND uac_bypass_tests)
    
    # Output directory per i test
    set_target_properties(uac_bypass_tests PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
endif()

# Copia file di configurazione nella directory di output
configure_file(${CMAKE_SOURCE_DIR}/include/Config.h
    ${CMAKE_BINARY_DIR}/bin/Config.h COPYONLY)
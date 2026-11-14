/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 *
 * C/C++ Header for WireGuard Windows Embeddable DLL (wireguard.dll / tunnel.dll)
 */

#ifndef WIREGUARD_H
#define WIREGUARD_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIREGUARD_EXPORTS
#    define WIREGUARD_API __declspec(dllexport)
#else
#    define WIREGUARD_API __declspec(dllimport)
#endif

/**
 * Log severity levels used by the WireGuard logger callback.
 */
typedef enum {
    WIREGUARD_LOG_INFO = 0,
    WIREGUARD_LOG_WARN = 1,
    WIREGUARD_LOG_ERR  = 2
} WIREGUARD_LOGGER_LEVEL;

/**
 * Function pointer type for logger callbacks.
 *
 * @param Level Log severity (0 = Info, 1 = Warn, 2 = Error).
 * @param Timestamp Seconds or nanoseconds since Unix epoch.
 * @param Message Null-terminated UTF-16 log message.
 */
typedef void (WINAPI *WIREGUARD_LOGGER_CALLBACK)(
    DWORD Level,
    DWORD64 Timestamp,
    LPCWSTR Message
);

/**
 * Runs the WireGuard tunnel service synchronously for the specified configuration file.
 * Blocks until the service is stopped via the Windows Service Control Manager.
 *
 * @param conf_file LPCWSTR path to the .conf or .conf.dpapi configuration file.
 * @return TRUE if the service ran and stopped successfully, FALSE on error.
 */
WIREGUARD_API BOOL WINAPI WireGuardTunnelService(LPCWSTR conf_file);

/**
 * Generates a new Curve25519 WireGuard keypair.
 * Generates cryptographically secure random bytes, applies standard WireGuard
 * Curve25519 clamping, and computes the corresponding public key.
 *
 * @param public_key Pointer to a buffer of at least 32 bytes to receive the public key.
 * @param private_key Pointer to a buffer of at least 32 bytes to receive the private key.
 * @return TRUE on success, FALSE if either pointer is NULL or RNG fails.
 */
WIREGUARD_API BOOL WINAPI WireGuardGenerateKey(BYTE *public_key, BYTE *private_key);

/**
 * Alias for WireGuardGenerateKey matching the original Go export name.
 *
 * @param public_key Pointer to a buffer of at least 32 bytes to receive the public key.
 * @param private_key Pointer to a buffer of at least 32 bytes to receive the private key.
 * @return TRUE on success, FALSE if either pointer is NULL or RNG fails.
 */
WIREGUARD_API BOOL WINAPI WireGuardGenerateKeypair(BYTE *public_key, BYTE *private_key);

/**
 * Sets or clears the global logger callback.
 *
 * @param callback Callback function pointer, or NULL to unregister.
 */
WIREGUARD_API void WINAPI WireGuardSetLogger(WIREGUARD_LOGGER_CALLBACK callback);

#ifdef __cplusplus
}
#endif

#endif /* WIREGUARD_H */

#pragma once

/**
 * Verify the classes.dex CRC-32 stored in the APK's ZIP central directory
 * against the compile-time constant EXPECTED_DEX_CRC32.
 *
 * @param apk_path  Absolute path to the APK file.
 *                  Pass ApplicationInfo.sourceDir from Kotlin.
 * @return true  if the CRC matches (APK is unmodified).
 *         false if the CRC mismatches or the APK cannot be read.
 *
 * Usage
 * ─────
 * After building a release APK, extract the expected CRC:
 *
 *   python3 -c "
 *   import zipfile, zlib, sys
 *   with zipfile.ZipFile(sys.argv[1]) as z:
 *       data = z.read('classes.dex')
 *   print(hex(zlib.crc32(data) & 0xFFFFFFFF))
 *   " release.apk
 *
 * Then replace EXPECTED_DEX_CRC32 in anti_tamper.cpp with that value and
 * rebuild before signing.
 */
bool verify_dex_crc32(const char* apk_path);

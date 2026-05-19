cmake_minimum_required(VERSION 3.22.1)

project("parental_control_native" VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---------------------------------------------------------------------------
# Security-hardened compiler flags
# ---------------------------------------------------------------------------
add_compile_options(
    -Wall
    -Wextra
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    -fPIC
    -O2
    # Strip symbol names from the shared object to harden reverse engineering
    -fvisibility=hidden
)

add_link_options(
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
)

# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
add_library(
    parental_control_native
    SHARED
    src/main/cpp/native-lib.cpp
    src/main/cpp/sni_parser.cpp
    src/main/cpp/watchdog.cpp
    src/main/cpp/anti_tamper.cpp
)

# ---------------------------------------------------------------------------
# NDK system libraries
# ---------------------------------------------------------------------------
find_library(log-lib     log)
find_library(android-lib android)

# ALooper lives in android, jnigraphics not needed here
target_link_libraries(
    parental_control_native
    ${log-lib}
    ${android-lib}
)

# ---------------------------------------------------------------------------
# Include directories
# ---------------------------------------------------------------------------
target_include_directories(
    parental_control_native
    PRIVATE
    src/main/cpp/include
)

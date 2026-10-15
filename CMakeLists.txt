cmake_minimum_required(VERSION 3.18)
project(pigeon C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wextra -Werror)

# Catches memory bugs and undefined behavior while we develop.
option(PIGEON_SANITIZE "Build with ASan + UBSan" ON)
if(PIGEON_SANITIZE)
    add_compile_options(-fsanitize=address,undefined -g)
    add_link_options(-fsanitize=address,undefined)
endif()

include_directories(src)

find_library(PCAP_LIBRARY pcap REQUIRED)

add_executable(pigeon
        src/main.c
        src/capture/capture.c
)

target_compile_definitions(pigeon PRIVATE PIGEON_VERSION="0.0.1")
target_link_libraries(pigeon PRIVATE ${PCAP_LIBRARY})

enable_testing()
add_executable(test_capture_file
        tests/unit/test_capture_file.c
        src/capture/capture.c)
target_compile_definitions(test_capture_file PRIVATE
        PIGEON_FIXTURE_DIR="${CMAKE_SOURCE_DIR}/tests/fixtures")
target_link_libraries(test_capture_file PRIVATE ${PCAP_LIBRARY})
add_test(NAME capture_file COMMAND test_capture_file)

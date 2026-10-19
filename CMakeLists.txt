cmake_minimum_required(VERSION 3.18)
project(pigeon C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wextra -Werror)

# Memory errors and undefined behavior abort the program, so a test run that
# hits either one fails. Without -fno-sanitize-recover, UBSan only prints a
# report and the run continues.
option(PIGEON_SANITIZE "Build with ASan + UBSan" ON)
if(PIGEON_SANITIZE)
    add_compile_options(-fsanitize=address,undefined
                        -fno-sanitize-recover=undefined -g)
    add_link_options(-fsanitize=address,undefined)
endif()

include_directories(src)

find_library(PCAP_LIBRARY pcap REQUIRED)

add_library(pigeon_core STATIC
        src/capture/capture.c
        src/proto/ethernet.c
        src/proto/ipv4.c
        src/proto/transport.c
        src/proto/packet.c
        src/proto/pktdump.c
        src/flow/flow_table.c
)
target_link_libraries(pigeon_core PUBLIC ${PCAP_LIBRARY})

add_executable(pigeon src/main.c)
target_compile_definitions(pigeon PRIVATE PIGEON_VERSION="0.0.1")
target_link_libraries(pigeon PRIVATE pigeon_core)

enable_testing()

add_executable(test_capture_file tests/unit/test_capture_file.c)
target_compile_definitions(test_capture_file PRIVATE
        PIGEON_FIXTURE_DIR="${CMAKE_SOURCE_DIR}/tests/fixtures")
target_link_libraries(test_capture_file PRIVATE pigeon_core)
add_test(NAME capture_file COMMAND test_capture_file)

add_executable(test_ethernet tests/unit/test_ethernet.c)
target_compile_definitions(test_ethernet PRIVATE
        PIGEON_FIXTURE_DIR="${CMAKE_SOURCE_DIR}/tests/fixtures")
target_link_libraries(test_ethernet PRIVATE pigeon_core)
add_test(NAME ethernet COMMAND test_ethernet)

add_executable(test_ipv4 tests/unit/test_ipv4.c)
target_compile_definitions(test_ipv4 PRIVATE
        PIGEON_FIXTURE_DIR="${CMAKE_SOURCE_DIR}/tests/fixtures")
target_link_libraries(test_ipv4 PRIVATE pigeon_core)
add_test(NAME ipv4 COMMAND test_ipv4)

add_executable(test_transport tests/unit/test_transport.c)
target_compile_definitions(test_transport PRIVATE
        PIGEON_FIXTURE_DIR="${CMAKE_SOURCE_DIR}/tests/fixtures")
target_link_libraries(test_transport PRIVATE pigeon_core)
add_test(NAME transport COMMAND test_transport)

add_executable(test_packet tests/unit/test_packet.c)
target_compile_definitions(test_packet PRIVATE
        PIGEON_FIXTURE_DIR="${CMAKE_SOURCE_DIR}/tests/fixtures")
target_link_libraries(test_packet PRIVATE pigeon_core)
add_test(NAME packet COMMAND test_packet)

add_test(NAME cli COMMAND ${CMAKE_COMMAND}
        -DPIGEON=$<TARGET_FILE:pigeon>
        -DFIXTURE=${CMAKE_SOURCE_DIR}/tests/fixtures/short_frames.pcap
        -P ${CMAKE_SOURCE_DIR}/tests/integration/test_cli.cmake)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_sources(pigeon_core PRIVATE src/net/netif_linux.c)

    add_executable(test_netif tests/unit/test_netif.c)
    target_link_libraries(test_netif PRIVATE pigeon_core)
    add_test(NAME netif COMMAND test_netif)
else()
    target_sources(pigeon_core PRIVATE src/net/netif_stub.c)
endif()

add_executable(test_netif_stub tests/unit/test_netif_stub.c src/net/netif_stub.c)
add_test(NAME netif_stub COMMAND test_netif_stub)

add_executable(test_flow_table tests/unit/test_flow_table.c)
target_link_libraries(test_flow_table PRIVATE pigeon_core)
add_test(NAME flow_table COMMAND test_flow_table)

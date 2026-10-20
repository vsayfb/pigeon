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
find_package(SQLite3 3.24 REQUIRED)
find_package(Threads REQUIRED)

add_library(pigeon_core STATIC
        src/capture/capture.c
        src/capture/select.c
        src/control/control.c
        src/proto/ethernet.c
        src/proto/ipv4.c
        src/proto/ipv6.c
        src/proto/address.c
        src/proto/transport.c
        src/proto/icmp.c
        src/proto/esp.c
        src/proto/quic.c
        src/proto/packet.c
        src/proto/pktdump.c
        src/flow/flow_table.c
        src/flow/flow.c
        src/app/app.c
        src/store/store.c
        src/dns/dns_parse.c
        src/dns/dns_cache.c
)
target_link_libraries(pigeon_core PUBLIC ${PCAP_LIBRARY} SQLite::SQLite3 Threads::Threads)

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
    target_sources(pigeon_core PRIVATE src/net/netif_linux.c src/app/app_linux.c)

    add_executable(test_netif tests/unit/test_netif.c)
    target_link_libraries(test_netif PRIVATE pigeon_core)
    add_test(NAME netif COMMAND test_netif)
else()
    target_sources(pigeon_core PRIVATE src/net/netif_stub.c src/app/app_stub.c)
endif()

add_executable(test_netif_stub tests/unit/test_netif_stub.c src/net/netif_stub.c)
add_test(NAME netif_stub COMMAND test_netif_stub)

add_executable(test_flow_table tests/unit/test_flow_table.c)
target_link_libraries(test_flow_table PRIVATE pigeon_core)
add_test(NAME flow_table COMMAND test_flow_table)

add_executable(test_flow tests/unit/test_flow.c)
target_link_libraries(test_flow PRIVATE pigeon_core)
add_test(NAME flow COMMAND test_flow)

add_executable(test_store tests/unit/test_store.c)
target_link_libraries(test_store PRIVATE pigeon_core)
add_test(NAME store COMMAND test_store)

add_executable(test_flow_flush tests/unit/test_flow_flush.c)
target_link_libraries(test_flow_flush PRIVATE pigeon_core)
add_test(NAME flow_flush COMMAND test_flow_flush)

add_executable(test_replay_store tests/integration/test_replay_store.c)
target_link_libraries(test_replay_store PRIVATE pigeon_core)
add_test(NAME replay_store COMMAND test_replay_store $<TARGET_FILE:pigeon>
        ${CMAKE_SOURCE_DIR}/tests/fixtures/short_frames.pcap
        ${CMAKE_SOURCE_DIR}/tests/fixtures/dns_before_flow.pcap
        ${CMAKE_SOURCE_DIR}/tests/fixtures/flow_before_dns.pcap
        ${CMAKE_SOURCE_DIR}/tests/fixtures/ipv6_conversations.pcap)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(test_capture_tick tests/unit/test_capture_tick.c)
    target_link_libraries(test_capture_tick PRIVATE pigeon_core)
    target_link_options(test_capture_tick PRIVATE
            -Wl,--wrap=pcap_open_live -Wl,--wrap=pcap_datalink
            -Wl,--wrap=pcap_get_selectable_fd -Wl,--wrap=pcap_setnonblock
            -Wl,--wrap=pcap_dispatch -Wl,--wrap=pcap_geterr -Wl,--wrap=pcap_breakloop
            -Wl,--wrap=pcap_close -Wl,--wrap=poll -Wl,--wrap=time)
    add_test(NAME capture_tick COMMAND test_capture_tick)
endif()

add_executable(test_dns_parse tests/unit/test_dns_parse.c)
target_compile_definitions(test_dns_parse PRIVATE
        PIGEON_FIXTURE_DIR="${CMAKE_SOURCE_DIR}/tests/fixtures")
target_link_libraries(test_dns_parse PRIVATE pigeon_core)
add_test(NAME dns_parse COMMAND test_dns_parse)

add_executable(fuzz_dns_parse tests/fuzz/fuzz_dns_parse.c)
target_link_libraries(fuzz_dns_parse PRIVATE pigeon_core)

add_executable(test_dns_cache tests/unit/test_dns_cache.c)
target_link_libraries(test_dns_cache PRIVATE pigeon_core)
add_test(NAME dns_cache COMMAND test_dns_cache)

add_executable(test_ipv6 tests/unit/test_ipv6.c)
target_link_libraries(test_ipv6 PRIVATE pigeon_core)
add_test(NAME ipv6 COMMAND test_ipv6)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(test_netif_addresses tests/unit/test_netif_addresses.c)
    target_link_libraries(test_netif_addresses PRIVATE pigeon_core)
    target_link_options(test_netif_addresses PRIVATE -Wl,--wrap=getifaddrs -Wl,--wrap=freeifaddrs
            -Wl,--wrap=socket -Wl,--wrap=connect -Wl,--wrap=getsockname -Wl,--wrap=close)
    add_test(NAME netif_addresses COMMAND test_netif_addresses)
endif()

add_executable(fuzz_packet tests/fuzz/fuzz_packet.c)
target_link_libraries(fuzz_packet PRIVATE pigeon_core)

set(CURSES_NEED_NCURSES TRUE)
set(CURSES_NEED_WIDE TRUE)

# Reconfigure existing build trees that previously selected narrow ncurses.
if(CURSES_NCURSES_LIBRARY AND NOT CURSES_NCURSES_LIBRARY MATCHES "ncursesw")
    unset(CURSES_NCURSES_LIBRARY CACHE)
endif()

find_package(Curses REQUIRED)

add_library(pigeon_tui_data STATIC src/tui/model.c src/proto/address.c)
target_link_libraries(pigeon_tui_data PUBLIC SQLite::SQLite3)

add_executable(pigeon-tui src/tui/main.c src/tui/screen.c src/tui/interfaces.c src/control/control.c)
target_include_directories(pigeon-tui PRIVATE ${CURSES_INCLUDE_DIRS})
target_compile_definitions(pigeon-tui PRIVATE _XOPEN_SOURCE=700 _XOPEN_SOURCE_EXTENDED=1)
target_link_libraries(pigeon-tui PRIVATE pigeon_tui_data ${CURSES_LIBRARIES})

add_executable(test_tui_model tests/unit/test_tui_model.c)
target_link_libraries(test_tui_model PRIVATE pigeon_tui_data pigeon_core)
add_test(NAME tui_model COMMAND test_tui_model)

add_executable(test_tui_screen tests/unit/test_tui_screen.c src/tui/screen.c)
target_include_directories(test_tui_screen PRIVATE ${CURSES_INCLUDE_DIRS})
target_compile_definitions(test_tui_screen PRIVATE _XOPEN_SOURCE=700 _XOPEN_SOURCE_EXTENDED=1)
target_link_libraries(test_tui_screen PRIVATE pigeon_tui_data ${CURSES_LIBRARIES})
add_test(NAME tui_screen COMMAND test_tui_screen)

add_executable(test_app tests/unit/test_app.c)
target_link_libraries(test_app PRIVATE pigeon_core)
add_test(NAME app COMMAND test_app)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(test_app_live tests/unit/test_app_live.c)
    target_link_libraries(test_app_live PRIVATE pigeon_core)
    add_test(NAME app_live COMMAND test_app_live)
endif()

add_executable(test_icmp tests/unit/test_icmp.c)
target_link_libraries(test_icmp PRIVATE pigeon_core)
add_test(NAME icmp COMMAND test_icmp)

add_test(NAME icmp_replay COMMAND ${CMAKE_COMMAND}
        -DPIGEON=$<TARGET_FILE:pigeon>
        -DFIXTURE=${CMAKE_SOURCE_DIR}/tests/fixtures/icmp_conversations.pcap
        -DBINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}
        -P ${CMAKE_SOURCE_DIR}/tests/integration/test_icmp.cmake)

add_executable(test_quic tests/unit/test_quic.c)
target_link_libraries(test_quic PRIVATE pigeon_core)
add_test(NAME quic COMMAND test_quic)

add_test(NAME quic_replay COMMAND ${CMAKE_COMMAND}
        -DPIGEON=$<TARGET_FILE:pigeon>
        -DFIXTURE=${CMAKE_SOURCE_DIR}/tests/fixtures/quic_conversations.pcap
        -DBINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}
        -P ${CMAKE_SOURCE_DIR}/tests/integration/test_quic.cmake)

add_executable(test_vlan tests/unit/test_vlan.c)
target_compile_definitions(test_vlan PRIVATE PIGEON_FIXTURE_DIR="${CMAKE_SOURCE_DIR}/tests/fixtures")
target_link_libraries(test_vlan PRIVATE pigeon_core)
add_test(NAME vlan COMMAND test_vlan)

add_executable(test_esp tests/unit/test_esp.c)
target_link_libraries(test_esp PRIVATE pigeon_core)
add_test(NAME esp COMMAND test_esp)

add_test(NAME vlan_esp_replay COMMAND ${CMAKE_COMMAND}
        -DPIGEON=$<TARGET_FILE:pigeon>
        -DFIXTURE=${CMAKE_SOURCE_DIR}/tests/fixtures/vlan_esp_conversations.pcap
        -DBINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}
        -P ${CMAKE_SOURCE_DIR}/tests/integration/test_vlan_esp.cmake)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(test_capture_select tests/unit/test_capture_select.c)
    target_link_libraries(test_capture_select PRIVATE pigeon_core)
    target_link_options(test_capture_select PRIVATE
            -Wl,--wrap=pcap_findalldevs -Wl,--wrap=pcap_freealldevs
            -Wl,--wrap=pcap_open_live -Wl,--wrap=pcap_datalink
            -Wl,--wrap=pcap_get_selectable_fd -Wl,--wrap=pcap_close)
    add_test(NAME capture_select COMMAND test_capture_select)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(test_control tests/unit/test_control.c)
    target_link_libraries(test_control PRIVATE pigeon_core)
    add_test(NAME control COMMAND test_control)

    add_executable(test_capture_switch tests/unit/test_capture_switch.c)
    target_link_libraries(test_capture_switch PRIVATE pigeon_core)
    target_link_options(test_capture_switch PRIVATE
            -Wl,--wrap=netif_select -Wl,--wrap=netif_addresses
            -Wl,--wrap=capture_select_interface -Wl,--wrap=capture_source_open
            -Wl,--wrap=capture_source_close -Wl,--wrap=capture_stop)
    add_test(NAME capture_switch COMMAND test_capture_switch)
endif()

add_executable(test_attribution_retry tests/unit/test_attribution_retry.c)
target_compile_definitions(test_attribution_retry PRIVATE PIGEON_FIXTURE_DIR="${CMAKE_SOURCE_DIR}/tests/fixtures")
target_link_libraries(test_attribution_retry PRIVATE pigeon_core)
add_test(NAME attribution_retry COMMAND test_attribution_retry)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(test_app_debug tests/unit/test_app_debug.c)
    target_link_libraries(test_app_debug PRIVATE pigeon_core)
    target_link_options(test_app_debug PRIVATE -Wl,--wrap=app_snapshot_read)
    add_test(NAME app_debug COMMAND test_app_debug)
endif()

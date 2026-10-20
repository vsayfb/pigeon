execute_process(COMMAND "${PIGEON}" --version
    RESULT_VARIABLE rc OUTPUT_VARIABLE output ERROR_VARIABLE errors)
if(NOT rc EQUAL 0 OR NOT output MATCHES "^pigeon [0-9]+\\.[0-9]+\\.[0-9]+\n$" OR NOT errors STREQUAL "")
    message(FATAL_ERROR "Version command failed: ${rc}: ${output} ${errors}")
endif()

execute_process(COMMAND "${PIGEON}" -r "${FIXTURE}"
    RESULT_VARIABLE rc OUTPUT_VARIABLE output ERROR_VARIABLE errors)
if(NOT rc EQUAL 0 OR NOT output STREQUAL "" OR
   NOT errors MATCHES "stopped after 4 packets")
    message(FATAL_ERROR "Quiet replay failed: ${rc}: ${output} ${errors}")
endif()

execute_process(COMMAND "${PIGEON}" -r "${FIXTURE}" --verbose
    RESULT_VARIABLE rc OUTPUT_VARIABLE output ERROR_VARIABLE errors)
if(NOT rc EQUAL 0 OR NOT output MATCHES "TCP 49152 > 80 hdr=20 payload=0" OR
   NOT output MATCHES "UDP 49152 > 9999 payload=1" OR
   NOT output MATCHES "IPv4 192.0.2.10 > 198.51.100.20" OR
   NOT output MATCHES "#4 caplen=60 wirelen=60")
    message(FATAL_ERROR "Verbose replay failed: ${rc}: ${output} ${errors}")
endif()

execute_process(COMMAND "${PIGEON}" --unknown
    RESULT_VARIABLE rc OUTPUT_VARIABLE output ERROR_VARIABLE errors)
if(NOT rc EQUAL 2 OR NOT errors MATCHES "usage:")
    message(FATAL_ERROR "Invalid arguments did not print usage")
endif()

execute_process(COMMAND "${PIGEON}" -r
    RESULT_VARIABLE rc OUTPUT_VARIABLE output ERROR_VARIABLE errors)
if(NOT rc EQUAL 2 OR NOT errors MATCHES "usage:")
    message(FATAL_ERROR "Missing replay path did not print usage")
endif()

execute_process(COMMAND "${PIGEON}" pigeon-missing-interface
    RESULT_VARIABLE rc OUTPUT_VARIABLE output ERROR_VARIABLE errors)
if(NOT rc EQUAL 1 OR NOT errors MATCHES "interface discovery")
    message(FATAL_ERROR "Invalid interface did not fail discovery: ${errors}")
endif()

execute_process(COMMAND "${PIGEON}" --verbose --local-ip 192.0.2.10 -r "${FIXTURE}"
    RESULT_VARIABLE rc OUTPUT_VARIABLE output ERROR_VARIABLE errors)
if(NOT rc EQUAL 0 OR NOT errors MATCHES "tracked 2 conversations" OR
   NOT output MATCHES "flow 192.0.2.10 > 198.51.100.20:80 proto=6 packets_out=2 packets_in=1 bytes_out=1 bytes_in=0 first_seen=1700000000 last_seen=1700000000" OR
   NOT output MATCHES "flow 192.0.2.10 > 198.51.100.20:9999 proto=17 packets_out=1 packets_in=0 bytes_out=1 bytes_in=0")
    message(FATAL_ERROR "Capture-to-flow replay failed: ${rc}: ${output} ${errors}")
endif()

get_filename_component(fixture_dir "${FIXTURE}" DIRECTORY)
execute_process(COMMAND "${PIGEON}" --verbose --local-ip 192.0.2.10
    -r "${fixture_dir}/tcp_handshake.pcap"
    RESULT_VARIABLE rc OUTPUT_VARIABLE output ERROR_VARIABLE errors)
if(NOT rc EQUAL 0 OR NOT errors MATCHES "tracked 1 conversations" OR
   NOT output MATCHES "proto=6 packets_out=3 packets_in=2 bytes_out=38 bytes_in=38 first_seen=1700000000 last_seen=1700000000")
    message(FATAL_ERROR "Handshake flow totals failed: ${rc}: ${output} ${errors}")
endif()

execute_process(COMMAND "${PIGEON}" --verbose --local-ip 198.51.100.20 -r "${FIXTURE}"
    RESULT_VARIABLE rc OUTPUT_VARIABLE output ERROR_VARIABLE errors)
if(NOT rc EQUAL 0 OR NOT errors MATCHES "tracked 2 conversations" OR
   NOT output MATCHES "flow 198.51.100.20 > 192.0.2.10:49152 proto=6 packets_out=1 packets_in=2 bytes_out=0 bytes_in=1" OR
   NOT output MATCHES "flow 198.51.100.20 > 192.0.2.10:49152 proto=17 packets_out=0 packets_in=1 bytes_out=0 bytes_in=1")
    message(FATAL_ERROR "Reverse direction totals failed: ${rc}: ${output} ${errors}")
endif()

execute_process(COMMAND "${PIGEON}" --local-ip 192.0.2.10 -r "${FIXTURE}"
    RESULT_VARIABLE rc OUTPUT_VARIABLE output ERROR_VARIABLE errors)
if(NOT rc EQUAL 0 OR NOT output STREQUAL "" OR
   NOT errors MATCHES "tracked 2 conversations")
    message(FATAL_ERROR "Quiet flow replay failed: ${rc}: ${output} ${errors}")
endif()

execute_process(COMMAND "${PIGEON}" --local-ip 203.0.113.1 -r "${FIXTURE}"
    RESULT_VARIABLE rc OUTPUT_VARIABLE output ERROR_VARIABLE errors)
if(NOT rc EQUAL 0 OR NOT errors MATCHES "tracked 0 conversations")
    message(FATAL_ERROR "Unrelated replay traffic was tracked: ${rc}: ${errors}")
endif()

execute_process(COMMAND "${PIGEON}" --local-ip bad-address -r "${FIXTURE}"
    RESULT_VARIABLE rc OUTPUT_VARIABLE output ERROR_VARIABLE errors)
if(NOT rc EQUAL 2 OR NOT errors MATCHES "invalid local IPv4")
    message(FATAL_ERROR "Invalid replay local address was accepted: ${errors}")
endif()

execute_process(COMMAND "${PIGEON}" --local-ip 192.0.2.10
    RESULT_VARIABLE rc OUTPUT_VARIABLE output ERROR_VARIABLE errors)
if(NOT rc EQUAL 2 OR NOT errors MATCHES "usage:")
    message(FATAL_ERROR "Live local-address override was accepted: ${errors}")
endif()

execute_process(COMMAND "${PIGEON}" --debug-attribution -r "${FIXTURE}"
    RESULT_VARIABLE rc OUTPUT_VARIABLE output ERROR_VARIABLE errors)
if(NOT rc EQUAL 2 OR NOT errors MATCHES "usage:")
    message(FATAL_ERROR "Offline attribution diagnostics were accepted: ${rc}: ${errors}")
endif()

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

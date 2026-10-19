string(RANDOM LENGTH 12 ALPHABET abcdef0123456789 suffix)
set(database "${BINARY_DIR}/icmp-${suffix}.db")
execute_process(COMMAND "${PIGEON}" --verbose --db "${database}"
    --local-ip 192.0.2.10 --local-ip 2001:db8::10 -r "${FIXTURE}"
    RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE errors)
file(REMOVE "${database}" "${database}-wal" "${database}-shm")
if(NOT result EQUAL 0)
    message(FATAL_ERROR "ICMP replay failed: ${result}\n${output}\n${errors}")
endif()
foreach(expected IN ITEMS
        "ICMP type=8 code=0" "ICMPv6 type=128 code=0"
        "flow 192.0.2.10 > 198.51.100.42 proto=1 packets_out=1 packets_in=1 bytes_out=4 bytes_in=4"
        "flow 2001:db8::10 > [2001:db8::42] proto=58 packets_out=1 packets_in=1 bytes_out=4 bytes_in=4"
        "flow 192.0.2.10 > 198.51.100.1 proto=1 packets_out=0 packets_in=1"
        "flow 2001:db8::10 > [2001:db8::1] proto=58 packets_out=0 packets_in=1")
    string(FIND "${output}" "${expected}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "Missing ${expected}\n${output}\n${errors}")
    endif()
endforeach()
if(NOT errors MATCHES "pigeon tracked 4 conversations")
    message(FATAL_ERROR "Expected four peers; local control must not be counted\n${errors}")
endif()

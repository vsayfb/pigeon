string(RANDOM LENGTH 12 ALPHABET abcdef0123456789 suffix)
set(database "${BINARY_DIR}/vlan-esp-${suffix}.db")
execute_process(COMMAND "${PIGEON}" --verbose --db "${database}"
    --local-ip 192.0.2.10 --local-ip 2001:db8::10 -r "${FIXTURE}"
    RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE errors)
file(REMOVE "${database}" "${database}-wal" "${database}-shm")
if(NOT result EQUAL 0)
    message(FATAL_ERROR "VLAN/ESP replay failed: ${result}\n${output}\n${errors}")
endif()
foreach(expected IN ITEMS
        "vlan=100(tpid=0x8100)" "vlan=200(tpid=0x88a8)"
        "ESP spi=0x00000001" "(ESP encapsulation)"
        "flow 192.0.2.10 > 198.51.100.42 proto=50 packets_out=2 packets_in=2 bytes_out=16 bytes_in=16"
        "flow 2001:db8::10 > [2001:db8::42] proto=50 packets_out=2 packets_in=2 bytes_out=16 bytes_in=16"
        "flow 192.0.2.10 > 198.51.100.99:443 proto=17 packets_out=1 packets_in=1 bytes_out=4 bytes_in=4"
        "flow 2001:db8::10 > [2001:db8::99]:443 proto=17 packets_out=1 packets_in=1 bytes_out=4 bytes_in=4"
        "flow 192.0.2.10 > 198.51.100.42:4500 proto=17 packets_out=2 packets_in=0 bytes_out=25 bytes_in=0")
    string(FIND "${output}" "${expected}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "Missing ${expected}\n${output}\n${errors}")
    endif()
endforeach()
if(NOT errors MATCHES "pigeon tracked 5 conversations")
    message(FATAL_ERROR "Expected five observations with no duplicate ESP-in-UDP counting\n${errors}")
endif()

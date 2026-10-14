cmake_minimum_required(VERSION 3.16)
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

add_executable(pigeon src/main.c)
target_compile_definitions(pigeon PRIVATE PIGEON_VERSION="0.0.1")

enable_testing()
add_executable(test_smoke tests/unit/test_smoke.c)
add_test(NAME smoke COMMAND test_smoke)
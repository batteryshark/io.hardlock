cmake_minimum_required(VERSION 3.16)
project(io_hardlock C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY  "C:\\ez2emu\\")
set(CMAKE_SHARED_LIBRARY_PREFIX  "")

add_library(io_hardlock SHARED ../kitchen_sink/kitchen_sink.h ../kitchen_sink/target.h ../kitchen_sink/ks.debug.c ../kitchen_sink/ks.memutils.h ../kitchen_sink/ks.memutils.c ../kitchen_sink/ks.hotpatch.c io.hardlock.c io.hardlock.emulator.c fastapi.h io.hardlock.emulator.h io.hardlock.hooks.c io.hardlock.hooks.h io.hardlock.internal.c io.hardlock.internal.h io.hardlock.protocol.c io.hardlock.protocol.h)
set_target_properties(io_hardlock PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
set_target_properties(io_hardlock PROPERTIES OUTPUT_NAME "io.hardlock")

project(tools_io_hardlock_seed_brute C)
add_executable(tools_io_hardlock_seed_brute io.hardlock.internal.c tools.io.hardlock.seed_brute.c)
set_target_properties(tools_io_hardlock_seed_brute PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
set_target_properties(tools_io_hardlock_seed_brute PROPERTIES OUTPUT_NAME "tools.io.hardlock.seed_brute")

project(tools_io_hardlock_test_packet C)
add_executable(tools_io_hardlock_test_packet io.hardlock.protocol.c tools.io.hardlock.test_packet.c)
set_target_properties(tools_io_hardlock_test_packet PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
set_target_properties(tools_io_hardlock_test_packet PROPERTIES OUTPUT_NAME "tools.io.hardlock.test_packet")

project(tools_io_hardlock_packet_info C)
add_executable(tools_io_hardlock_packet_info ../kitchen_sink/ks.misc.c io.hardlock.protocol.c tools.io.hardlock.packet_info.c)
set_target_properties(tools_io_hardlock_packet_info PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
set_target_properties(tools_io_hardlock_packet_info PROPERTIES OUTPUT_NAME "tools.io.hardlock.packet_info")
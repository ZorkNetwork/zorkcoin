add_executable(test_kernel
    test_kernel.cpp
)
set_target_properties(test_kernel PROPERTIES OUTPUT_NAME test_zorkcoin_kernel)

target_link_libraries(test_kernel
  PRIVATE
    core_interface
    bitcoinkernel
    Boost::headers
)

add_windows_application_manifest(test_kernel)

add_test(NAME test_kernel COMMAND test_kernel)

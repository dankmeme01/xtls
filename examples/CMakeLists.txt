file(GLOB XTLS_EXAMPLE_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp"
)

foreach(example_src ${XTLS_EXAMPLE_SOURCES})
    get_filename_component(example_name ${example_src} NAME_WE)
    add_executable(xtls_${example_name} ${example_src})

    target_link_libraries(xtls_${example_name} PRIVATE xtls GeodeResult)
    set_target_properties(xtls_${example_name} PROPERTIES FOLDER "examples")

    if (XTLS_FEATURE_ASAN)
        target_compile_options(xtls_${example_name} PRIVATE -fsanitize=address -fsanitize=leak -fno-omit-frame-pointer -g)
        target_link_options(xtls_${example_name} PRIVATE -fsanitize=address -fsanitize=leak)
    endif()
endforeach()

cmake_minimum_required(VERSION 3.14)
project(ProjectName)

add_custom_target(dependencies_built)

add_custom_target(plog_external)
add_custom_target(openssl_external)
add_custom_target(googletest_external)

add_subdirectory(plog)
add_subdirectory(openssl)
add_subdirectory(googletest)

add_dependencies(plog_external    dependencies_built)
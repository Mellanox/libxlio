cmake_minimum_required(VERSION 3.12)
project(tx_scheduler)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
	  googletest
		URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)
# Enable testing
enable_testing()

# Add your source files
set(SOURCE_FILES
	tx_scheduler_test.cpp
	tx_scheduler.cpp
)

# Create an executable for your project
add_executable(tx_scheduler_test ${SOURCE_FILES})

# Link Google Test libraries
target_link_libraries(tx_scheduler_test GTest::gtest GTest::gtest_main gmock gmock_main)
include(GoogleTest)
gtest_discover_tests(tx_scheduler_test)

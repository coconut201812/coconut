# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.

add_definitions(-DNDEBUG -D_IPP_v50_ -D_IPP_DEBUG -D_DISABLE_ALG_MD5_ -D_DISABLE_ALG_SM3_)

file(GLOB utils_srcfiles "./src/*.c")

include_directories(../)
include_directories(../../../../libs/epid/include)

add_library( # Sets the name of the library.
              utils
             # Sets the library as a shared library.
              STATIC
             # Provides a relative path to your source file(s).
              ${utils_srcfiles})

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build
# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.

add_subdirectory(src/main/cpp/util)
add_subdirectory(src/main/cpp/sigmsg)

#define the final target to be realeased, a shared library, so
add_library(# Sets the name of the library.
             CoconutMcSDK

             # Sets the library as a shared library.
             SHARED

             # Provides a relative path to your source file(s).
             src/main/cpp/native-lib.cpp)

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.


find_library(ZLIB z)

#import openssl libcrypto.a
add_library(openssl_crypto STATIC IMPORTED)
set_target_properties(openssl_crypto
  PROPERTIES IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/libs/openssl/lib/openssl-${ANDROID_ABI}/libcrypto.a)

#import epid libcommon.a
add_library(epid_common STATIC IMPORTED)
set_target_properties(epid_common
  PROPERTIES IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/libs/epid/lib/epid-${ANDROID_ABI}/debug/libcommon.a)

#import epid libmember.a
add_library(epid_member STATIC IMPORTED)
set_target_properties(epid_member
  PROPERTIES IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/libs/epid/lib/epid-${ANDROID_ABI}/debug/libmember.a)

#import epid libipp.a
add_library(epid_ipp STATIC IMPORTED)
set_target_properties(epid_ipp
  PROPERTIES IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/libs/epid/lib/epid-${ANDROID_ABI}/debug/libipp.a)

# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.

#link libutils.a to the shared library(libCoconutMcSDK.so)
target_link_libraries(
                       # Specifies the target library.
                       CoconutMcSDK
                       -Wl,--whole-archive

                       utils
                       -Wl,--no-whole-archive
                      )

#link libsigmsg.a to the shared library(libCoconutMcSDK.so)
target_link_libraries(
                       # Specifies the target library.
                       CoconutMcSDK
                       -Wl,--whole-archive

                       sigmsg
                       -Wl,--no-whole-archive
                      )

#link libcommon.a to the share libray(libCoconutMcSDK.so)	      
target_link_libraries(
                       # Specifies the target library.
                       CoconutMcSDK
                       epid_common
                     )
		     
#link libmember.a to the share libray(libCoconutMcSDK.so)	      
target_link_libraries(
                       # Specifies the target library.
                       CoconutMcSDK
                       epid_member
                     )

#link libipp.a to the share libray(libCoconutMcSDK.so)	      
target_link_libraries(
                       # Specifies the target library.
                       CoconutMcSDK
                       epid_ipp
                     )

#link libcrypto.a to the share libray(libCoconutMcSDK.so)	      
target_link_libraries(
                       # Specifies the target library.
                       CoconutMcSDK
                       openssl_crypto
                       ${ZLIB}
                      )
1.Basic function of the software
  Coconut SDK provide the related functions of the Intel® EPID certificate application and use, 
  including generating join request for applying for EPID certificate online, 
  generating EPID member private key locally, making all signatures responding to every basename in the basename list 
  and signing message specified by the certificate holder. Additionally, the SDK provide the interface to load test data,
  such as group public key, member private key, basename list, so that the SDK interfaces can be tested very conveniently.
  
 2.Development environment
  android:
  compiler:  NDK r17 tools chain
  IDE:  android studio 3.1.4
  -------------------------------------
  iOS:
  compiler:  Apple LLVM 9.0 
  IDE:  xCode 9.4.1
  
 3.used libs in the project
 1) Intel® EPID SDK 7.0.0, you can also download and compile for android and iOS from github(https://github.com/Intel-EPID-SDK/epid-sdk)
 2) openssl 1.1.0i, you can also download and compile for android and iOS from github(https://github.com/openssl/openssl)
   
4.Runtime environment
  operating system: android
  processor architecture: armv7/arm64/x86/x86_64
  ------------------------------------------------
  operating system: iOS
  processor architecture: armv7/arm64

5. API references
   see coconut_SDK_for_mobileClient_manual.docx
  
6. Software version
  1.0.0

7. Security notice
The pseudo-random number generator used in the project is only suitable in the Specific application scenario,
you can choose more suitable algorithm for cryptographically secure applications.
   
The member private key should be saved securely, AES256 is used in the project, you can choose more suitable for your application.


  
 
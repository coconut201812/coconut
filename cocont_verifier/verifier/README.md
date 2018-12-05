1.Basic function of the software
  As a verifier demo of coconut, this software undertakes the task of verifying signatures. 
  This software should not be used in production environment.

2.Development environment
  java version: 10.0.1
  maven version: 3.5.4
  tomcat version: 9.0.8
  IDE: eclipse
  
3.Runtime environment
  operating system: linux
  processor architecture: X86_64
  
4.Introduction to project structure
  verifier/
  |__ src/
  |   |__ coconut/                                        Wrapping code for invoking coconut verifier SDK dynamic link library
  |   |__ main/
  |       |__ resources/
  |           |__ applicationContext.xml                  Configuration file of spring framework
  |           |__ epid_basenames.dat                      Sample data of basenames
  |           |__ epid_pubkey.bin                         Sample data of EPID group public key
  |           |__ libverifysig.so                         Enhanced Privacy ID (Intel® EPID) dynamic link library
  |       |__ transaction/                                Source for accepting and verifying signature
  |__ pom.xml                                             Configuration file of maven
  |__ sslCertification/
  |   |__ verifier_ks                                     Sample verifier server's certificate keystore
  |   |__ trust_ks                                        Sample verifier server's trust keystore
  |   |__ WebContent/
  |       |__ WEB-INF
  |           |__ web.xml                                 Configuration file of web service
  |       |__ index.jsp                                   Welcome page
  |__ README.txt                                          Readme
  
5.Methods of compiling
  1)Open command line tools, cd to the project directory；
  2)if the compile command was executed, execute command:mvn clean at first.
  3)Execute command:mvn install，find the war file in directory target.

6.System deployment procedures
  1)Install tomcat;
  2)Configure bidirectional authentication ssl certificate for tomcat;
  6)Compile and deploy war to tomcat;
  7)Start tomcat.

7.Software version
  1.0.0
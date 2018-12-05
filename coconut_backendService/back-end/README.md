1.Basic function of the software
  As backend service of the coconut, this software undertakes the task of integrating multi-nodes and supplying service for clients. 
  Backend service contains following modules:
  1)Interaction with certificate issuer module;
  2)Interaction with KYC module;
  3)Interaction with verifier module;
  
2.Development environment
  java version: 10.0.1
  maven version: 3.5.4
  tomcat version: 9.0.8
  mysql version: 8.0.11
  IDE: eclipse
  
3.Introduction to project structure
  back-end/
  |__ src/
  |   |__ coconut/                                        Source for coconut backend service
  |   |__ resources/
  |       |__ applicationContext.xml                      Configuration file of spring framework
  |       |__ basenames.json                              Configuration file of Basename array
  |       |__ datasource.properties                       Configuration file of Data source
  |       |__ epid.properties                             Configuration file of Enhanced Privacy ID (Intel® EPID)
  |       |__ IOT_CAK_IssuingCA0_VendID160.der            Authentication certification of EPID service(This is a sample one. You need 
                                                          to purchase certification issuer's service to get the IOT_CAK_IssuingCA0_VendID160.der)
  |       |__ log4j2.xml                                  Configuration file of log4j2
  |       |__ sslCertification.properties                 Configuration file of ssl certificate
  |__ pom.xml                                             Configuration file of maven
  |__ doc/
  |   |__ coconut_backend_RESTAPI_manual.docx             Manual of RESTful API
  |   |__ postman request/                                Sample requests exported from postman
  |__ sslCertification/
  |   |__ coconut_ks                                      Sample server's certificate keystore
  |   |__ trust_ks                                        Sample server's trust keystore
  |   |__ WebContent/
  |       |__ META-INF
  |       |__ WEB-INF
  |           |__ web.xml                                 Configuration file of web service
  |       |__ index.jsp                                   Welcome page
  |__ README.txt                                       Readme
  
4.Methods of compiling
  1)Open command line tools, change directory to the project directory.
  2)if the compile command was executed, execute command:mvn clean at first.
  3)Execute command:mvn install. Find the war file in directory target.
  
5.System deployment procedures
  1)Install tomcat.
  2)Only HTTPS APIs should be provided. Tomcat's HTTPS service should be configured well and it's HTTP service should be closed.
  3)Install mysql，and create a database named coconut.
  4)Modify configuration files to fit your runtime environment.
  5)Add verifier's and certification issuer's HTTPS certification to the keystore pointed by configuration file.
  6)Compile and deploy the war file to tomcat.
  7)Start tomcat.
  
  Notice: some part of the system is not automated in this version, you should do following jobs manually to Make the program run normally.
  1)Table TBL_business_info should be maintained manually, such as adding a business, drop a business and so on.
  2)Table TBL_group_info should be maintained manually, such as adding a certification group, drop a certification group and so on.
  3)Before adding a certification group, you should create a table named TBL_BK_info_? which is used to record BK. The ? means group id in 
    hexadecimal string format.
    The creation statement is:
    create table if not exists coconut.TBL_BK_info_? 
    (bk varchar(255) not null unique, 
     bk_md5 varchar(45) not null, 
     epid_part_certification varchar(255) not null, 
     primary key(bk),
     foreign key (epid_part_certification) references coconut.TBL_epid_certification_info(epid_part_certification));

  
6. API references
   see coconut_backend_RESTAPI_manual.docx

7.Software version
  1.0.0
  
8. Security notice
  This software communicates with verifier in bidirectional authentication mode with TLSv1.2 protocol. And certifies itself to clients by 
tomcat's HTTPS service. If you think it can't meet your security requirements, you can implement another communication mode.
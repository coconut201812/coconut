/*############################################################################
  # Copyright 2018 BITMAINTECH PTE LTD.
  #
  # Licensed under the Apache License, Version 2.0 (the "License");
  # you may not use this file except in compliance with the License.
  # You may obtain a copy of the License at
  #
  #     http://www.apache.org/licenses/LICENSE-2.0
  #
  # Unless required by applicable law or agreed to in writing, software
  # distributed under the License is distributed on an "AS IS" BASIS,
  # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  # See the License for the specific language governing permissions and
  # limitations under the License.
############################################################################*/
package coconut.svcsdk.common;

import java.io.InputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;

import org.apache.ibatis.io.Resources;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import coconut.svcsdk.common.Configuration;
import coconut.svcsdk.epid.EpidConnFactory;
import coconut.svcsdk.transaction.ConnectionPool;

/* coconut initialization class */
public class Initialization extends HttpServlet {
	private static final long serialVersionUID = 1L;
	
	// log4j
	private Logger logger = LogManager.getLogger(Initialization.class);

	/* Database initialization */
	private void DBinit() throws Exception {
		// Read configuration of database.
		String url = null;
		String user = null;
		String password = null;
		String driverClassName = null;
		InputStream dbPropertiesIn = Resources.getResourceAsStream("datasource.properties");
		try {
			Properties properties = new Properties();
			properties.load(dbPropertiesIn);
			url = properties.getProperty("db.url");
			user = properties.getProperty("db.username");
			password = properties.getProperty("db.password");
			driverClassName = properties.getProperty("db.driverClassName");
		} catch (Exception e) {
			throw e;
		} finally {
			dbPropertiesIn.close();
		}
		
		// Create or complete tables in database.
		Class.forName(driverClassName);
		Connection con = DriverManager.getConnection(url, user, password);
		try {
			con.setAutoCommit(false);
			Statement stmt = con.createStatement();
			try {
				// TBL_user_info
				String userInfoSql = "create table if not exists coconut.TBL_user_info "
												+ "(user_id integer not null AUTO_INCREMENT, "
												+ "user_password varchar(32), "
												+ "user_password_salt varchar(32), "
												+ "epid_request_attempt_times_max integer not null default 3, "
												+ "kyc_request_attempt_times_max integer not null default 3, "
												+ "tel varchar(128) unique, "
												+ "email varchar(320) unique, "
												+ "primary key(user_id));";
				stmt.addBatch(userInfoSql);
				
				// TBL_transaction_info_jumio
				String transactionInfoJumioSql = "create table if not exists coconut.TBL_transaction_info_jumio "
												+ "(transaction_reference varchar(255) not null unique,"
												+ "user_id integer not null,"
												+ "transaction_timestamp datetime,"
												+ "transaction_status varchar(16) default 'PENDING', "
												+ "transaction_url varchar(1024) not null, "
												+ "reject_reason varchar(1024), "
												+ "primary key(transaction_reference), "
												+ "foreign key (user_id) references coconut.TBL_user_info(user_id));";
				stmt.addBatch(transactionInfoJumioSql);
				
				// TBL_group_info
				String groupInfoSql = "create table if not exists coconut.TBL_group_info "
												+ "(group_id varchar(128) not null unique,"
												+ "group_id_hex varchar(128) not null unique,"
												+ "group_pub_key varchar(255) not null,"
												+ "kyc varchar(64) not null,"
												+ "primary key(group_id));";
				stmt.addBatch(groupInfoSql);
				
				// TBL_epid_certification_info
				String certificationInfoSql = "create table if not exists coconut.TBL_epid_certification_info "
												+ "(epid_part_certification varchar(255) not null unique,"
												+ "user_id integer not null,"
												+ "group_id varchar(128) not null,"
												+ "publish_timestamp datetime,"
												+ "revoke_flag integer not null default 0,"
												+ "signature varchar(6400),"
												+ "primary key(epid_part_certification),"
												+ "foreign key (user_id) references coconut.TBL_user_info(user_id),"
												+ "foreign key (group_id) references coconut.TBL_group_info(group_id));";
				stmt.addBatch(certificationInfoSql);
						
				// TBL_business_info
				String bussinessInfoSql = "create table if not exists coconut.TBL_business_info "
												+ "(verifier varchar(64) not null,"
												+ "kyc varchar(64) not null,"
												+ "verifier_address varchar(1024) not null,"
												+ "primary key(verifier,kyc));";
				stmt.addBatch(bussinessInfoSql);
				
				// set update mode
				String updateModeSql = "SET SQL_SAFE_UPDATES=0;";
				stmt.addBatch(updateModeSql);
				
				stmt.executeBatch();
				con.commit();
			} catch (SQLException e) {
				// Do roll back operation when exception occurs during executing sql statements.
				con.rollback();
				throw e;
			} finally {
				stmt.close();
			}
		} catch (SQLException e) {
			throw e;
		} finally {
			con.setAutoCommit(true);
			con.close();
		}
		
		return;
	}
	
	// Initialization function. Only can be invoked in web.xml. Quit if exception occurs.
	public void init() throws ServletException {
		logger.info("INITIALIZE BEGIN.");
		super.init();
		
		try {
			// Initialization of configuration.
			logger.info("CONFIGURATION INITIALIZE BEGIN.");
			Configuration.getInstance().ConfigInit();
			logger.info("CONFIGURATION INITIALIZE END.");
		
			// Initialization of database.
			logger.info("DATABASE INITIALIZE BEGIN.");
			DBinit();
			logger.info("DATABASE INITIALIZE END.");
			
			// Initialization of keep-alive connection pool.
			logger.info("CLIENTMANAGER INITIALIZE BEGIN.");
			ConnectionPool.getInstance().init();
			logger.info("CLIENTMANAGER INITIALIZE END.");
			
			// Initialization of EPID connection factory.
			logger.info("CLIENTMANAGER INITIALIZE BEGIN.");
			EpidConnFactory.getInstance().init();
			logger.info("CLIENTMANAGER INITIALIZE END.");
		} catch (Exception e) {
			// Quit if exception occurs.
			logger.error("Coconut initialization failed.", e);
			destroy();
			System.exit(-1);
		}
		logger.info("INITIALIZE END.");
		return;
	}
	
	/* Function for recycling */
	public void destroy() {
		ConnectionPool.getInstance().destroy();
		return;
	}
}

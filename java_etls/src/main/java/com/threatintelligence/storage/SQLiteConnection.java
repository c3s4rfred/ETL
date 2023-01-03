package com.threatintelligence.storage;

import com.threatintelligence.entity.transform.jobs.ElementListJob;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.sql.*;

/**
 * @author FRLA
 */
public class SQLiteConnection {
        private static final Logger log = LoggerFactory.getLogger(SQLiteConnection.class);
        private static final String CLASSNAME = "SQLiteConnection";
        private static Connection conn = null;

        public SQLiteConnection () throws SQLException {
            if (conn == null || conn.isClosed()) {
                connect();
            }
        }
        /**
         * Connect to a database, create if not exists
         */
        private static void connect() throws SQLException {
                final String ctx = CLASSNAME + ".connect";
                File parentFolder = new File("local_storage");
                if (!parentFolder.exists()) {
                    parentFolder.mkdir();
                }
                // db parameters
                String url = "jdbc:sqlite:local_storage/tw_etl_database.db";
                // create a connection to the database
                conn = DriverManager.getConnection(url);
                createTableProcessedValues();
                log.info("Connection to ETL local storage has been established.");
        }
        // Method to close the connection
        public static void closeCXN() throws SQLException{
                if (conn != null) {
                    conn.close();
                }
        }
        // Method to create table if not exists
        private static void createTableProcessedValues() throws SQLException {
            // SQL statement for creating a new table
            String sql = "CREATE TABLE IF NOT EXISTS t_etl_processed_values (\n"
                    + " ID INTEGER PRIMARY KEY AUTOINCREMENT,\n"
                    + " V_TYPE TEXT NOT NULL,\n"
                    + " VALUE TEXT NOT NULL\n"
                    + ");";

                Statement stmt = conn.createStatement();
                stmt.execute(sql);
        }
        // Method to insert a record into the table
        public static void insert(String type, String value) throws SQLException {
            String sql = "INSERT INTO t_etl_processed_values(V_TYPE, VALUE) VALUES(?,?)";
                PreparedStatement pstmt = conn.prepareStatement(sql);
                pstmt.setString(1, type);
                pstmt.setString(2, value);
                pstmt.executeUpdate();
        }
        // Method to check if a record exists
        public static boolean isAlreadyInserted(String type, String value) throws SQLException{
            String sql = "SELECT count(id) as counter FROM t_etl_processed_values where V_TYPE = '"+type+"' and VALUE = '"+value+"'";
                Statement stmt  = conn.createStatement();
                ResultSet rs    = stmt.executeQuery(sql);

                // loop through the result set
                if (rs.next()) {
                    int counter = rs.getInt("counter");
                    if (counter > 0) {
                        return true;
                    }

                }
                return false;
        }
}

/*
 * VulnService - a deliberately vulnerable demo class used ONLY to test VulnHunter's
 * multi-language scanner coverage. DO NOT deploy this anywhere. It contains intentional
 * security flaws for demonstration purposes only.
 *
 * Planted vulnerabilities (for scoring / demo reference):
 *   1. SQL Injection via Statement (string concat)   -> CWE-89
 *   2. Insecure deserialization (ObjectInputStream)   -> CWE-502
 *   3. Hardcoded credential                           -> CWE-798
 */

import java.io.*;
import java.net.Socket;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class VulnService {

    // VULN 3: Hardcoded credential (CWE-798) - should come from a secrets manager / env var
    private static final String DB_PASSWORD = "SuperSecretP@ss123";
    private static final String DB_URL = "jdbc:mysql://localhost:3306/vulnshop";
    private static final String DB_USER = "vulnshop_admin";

    /**
     * VULN 1: SQL Injection (CWE-89) - user-controlled username is concatenated
     * directly into the query string instead of using a PreparedStatement.
     */
    public String lookupUserByName(String username) throws Exception {
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
        Statement stmt = conn.createStatement();
        String query = "SELECT id, email FROM users WHERE username = '" + username + "'";
        ResultSet rs = stmt.executeQuery(query);

        StringBuilder result = new StringBuilder();
        while (rs.next()) {
            result.append(rs.getString("email"));
        }
        rs.close();
        stmt.close();
        conn.close();
        return result.toString();
    }

    /**
     * VULN 2: Insecure deserialization (CWE-502) - readObject() is called directly on
     * bytes received from an untrusted network socket, with no type filtering or
     * validation before deserializing.
     */
    public Object handleIncomingSession(Socket clientSocket) throws IOException, ClassNotFoundException {
        InputStream rawIn = clientSocket.getInputStream();
        ObjectInputStream ois = new ObjectInputStream(rawIn);
        // No allow-list, no ObjectInputFilter - any gadget chain on the classpath can run.
        Object sessionObject = ois.readObject();
        ois.close();
        return sessionObject;
    }

    public static void main(String[] args) throws Exception {
        VulnService service = new VulnService();
        System.out.println(service.lookupUserByName(args.length > 0 ? args[0] : "demo"));
    }
}

import java.io.*;
import java.net.*;
import java.sql.*;
import java.util.*;
import java.security.*;
import javax.servlet.*;
import javax.servlet.http.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.xml.parsers.*;
import org.w3c.dom.*;
import java.nio.file.*;
import javax.naming.*;
import javax.naming.directory.*;

public class VulnerableJavaApp {

    public void sqlInjectionVuln1(HttpServletRequest request) throws SQLException {
        String userId = request.getParameter("userId");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/testdb");
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        ResultSet rs = stmt.executeQuery(query);
    }

    public void sqlInjectionVuln2(String username) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/testdb");
        Statement stmt = conn.createStatement();
        String query = String.format("SELECT * FROM users WHERE username = '%s'", username);
        ResultSet rs = stmt.executeQuery(query);
    }

    public void commandInjectionVuln1(HttpServletRequest request) throws IOException {
        String filename = request.getParameter("file");
        Runtime.getRuntime().exec("cat " + filename);
    }

    public void commandInjectionVuln2(String userInput) throws IOException {
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", "echo " + userInput);
        pb.start();
    }

    public void pathTraversalVuln1(HttpServletRequest request) throws IOException {
        String filename = request.getParameter("filename");
        File file = new File("/var/www/files/" + filename);
        FileInputStream fis = new FileInputStream(file);
    }

    public void pathTraversalVuln2(String userPath) throws IOException {
        Path path = Paths.get("/uploads/" + userPath);
        Files.readAllBytes(path);
    }

    public void xssVuln1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("name");
        PrintWriter out = response.getWriter();
        out.println("<html><body>Hello " + userInput + "</body></html>");
    }

    public void xssVuln2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String comment = request.getParameter("comment");
        response.getWriter().write("<div>" + comment + "</div>");
    }

    public void xxeVuln1(String xmlInput) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(new ByteArrayInputStream(xmlInput.getBytes()));
    }

    public void xxeVuln2(InputStream xmlStream) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(xmlStream);
    }

    public void deserializationVuln(HttpServletRequest request) throws Exception {
        InputStream is = request.getInputStream();
        ObjectInputStream ois = new ObjectInputStream(is);
        Object obj = ois.readObject();
    }

    public String weakCryptoMD5(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }

    public String weakCryptoSHA1(String data) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA1");
        byte[] hash = md.digest(data.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }

    public byte[] weakEncryptionDES(String plaintext, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(plaintext.getBytes());
    }

    public String insecureRandomVuln() {
        Random random = new Random();
        return String.valueOf(random.nextInt());
    }

    public String generateToken() {
        Random rand = new Random();
        return "TOKEN_" + rand.nextLong();
    }

    public Connection hardcodedCredsVuln1() throws SQLException {
        String username = "admin";
        String password = "admin123";
        return DriverManager.getConnection("jdbc:mysql://localhost/db", username, password);
    }

    public void hardcodedCredsVuln2() {
        String apiKey = "sk-1234567890abcdef";
        String apiSecret = "secret_abc123xyz789";
    }

    public void ldapInjectionVuln(String username) throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        DirContext ctx = new InitialDirContext(env);
        String filter = "(&(uid=" + username + "))";
        ctx.search("ou=users,dc=example,dc=com", filter, new SearchControls());
    }

    public void logForgingVuln(HttpServletRequest request) {
        String username = request.getParameter("username");
        System.out.println("User logged in: " + username);
    }

    public void insecureCookieVuln1(HttpServletResponse response) {
        Cookie cookie = new Cookie("sessionId", "abc123");
        cookie.setMaxAge(3600);
        response.addCookie(cookie);
    }

    public void insecureCookieVuln2(HttpServletResponse response) {
        Cookie cookie = new Cookie("token", "xyz789");
        cookie.setHttpOnly(true);
        response.addCookie(cookie);
    }

    public void openRedirectVuln(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String redirectUrl = request.getParameter("redirect");
        response.sendRedirect(redirectUrl);
    }

    public void ssrfVuln1(String userUrl) throws IOException {
        URL url = new URL(userUrl);
        URLConnection conn = url.openConnection();
        InputStream is = conn.getInputStream();
    }

    public void ssrfVuln2(HttpServletRequest request) throws IOException {
        String targetUrl = request.getParameter("url");
        URL url = new URL(targetUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.connect();
    }

    public void insecureFileUpload(HttpServletRequest request) throws Exception {
        Part filePart = request.getPart("file");
        String fileName = filePart.getSubmittedFileName();
        filePart.write("/uploads/" + fileName);
    }

    public void massAssignmentVuln(HttpServletRequest request, User user) {
        Enumeration<String> params = request.getParameterNames();
        while (params.hasMoreElements()) {
            String param = params.nextElement();
            String value = request.getParameter(param);
        }
    }

    public byte[] nullCipherVuln(String data) throws Exception {
        Cipher cipher = Cipher.getInstance("NULL");
        return cipher.doFinal(data.getBytes());
    }

    public byte[] staticIVVuln(String plaintext, String key) throws Exception {
        byte[] iv = new byte[16];
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        return cipher.doFinal(plaintext.getBytes());
    }

    public void trustAllCertsVuln() throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
                public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                }
                public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                }
            }
        };
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
    }

    public boolean redosVuln(String input) {
        return input.matches("(a+)+b");
    }

    public void informationExposureVuln(HttpServletResponse response) {
        try {
        } catch (Exception e) {
            try {
                e.printStackTrace(response.getWriter());
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }

    public String weakPasswordStorage(String password) {
        return password;
    }

    public String deprecatedHash(String data) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD2");
        byte[] hash = md.digest(data.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }

    public void cleartextTransmission(String sensitiveData) throws IOException {
        Socket socket = new Socket("example.com", 80);
        PrintWriter out = new PrintWriter(socket.getOutputStream());
        out.println(sensitiveData);
    }

    class User {
        private String username;
        private String email;
        private boolean isAdmin;
    }
}

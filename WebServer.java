
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class WebServer extends Thread {

    //hashmap for storing key-value config pairs after reading .conf file
    private Map<String, String> configs = new HashMap<>();

    //hashmap for storing key-value mime-type pairs after reading mime.type file
    private Map<String, String> mimeTypes = new HashMap<>();

    private int webServerPort;

    private String authUserFile = "";

    //thread list for keeoing track of client connections
    private ArrayList<WebServerThreads> threadList = new ArrayList<>();

    public static void main(String[] args) {
        WebServer webServer = new WebServer();
        webServer.start();
    }

    public List<WebServerThreads> getThreadList() {
        return threadList;
    }

    public Map<String, String> getMimeTypes() {
        return mimeTypes;
    }

    public Map<String, String> getConfigs() {
        return configs;
    }

    public String getAuthUserFile() {
        return authUserFile;
    }

    private void initMimeTypes() {
        try {
            FileReader fileReader = new FileReader("./conf/mime.types");
            BufferedReader bufferedReader = new BufferedReader(fileReader);

            String line;
            Boolean endOfComments = false;
            while ((line = bufferedReader.readLine()) != null) {

                if (line.contains("Extensions")) {
                    endOfComments = true;
                    line = bufferedReader.readLine();
                }
                if (endOfComments) {
                    String[] str = line.split("\\s");
                    String value = str[0];
                    for (int i = 1; i < str.length; i++) {
                        String key = str[i].strip();
                        if (!key.isEmpty()) {
                            mimeTypes.put(key, value);
                        }
                    }
                }
            }
            fileReader.close();

        } catch (IOException exception) {
            System.out.println("mime File not found");
        }
    }

    private void inithtaccessFile() {
        try {
            FileReader fileReader = new FileReader("./htaaccess.txt");
            BufferedReader bufferedReader = new BufferedReader(fileReader);

            String line;
            while ((line = bufferedReader.readLine()) != null) {

                String[] lineTokens = line.split(" ");
                authUserFile = lineTokens[1].replaceAll("^\"|\"$", "");
                System.out.println("AuthUserFile Initialized Successfully: " + authUserFile);

            }

        } catch (IOException exception) {
            System.out.println("htaccess File not found");
        }
    }

    //read configurations from .conf file and store them in config hashmap, while also initializing server port value
    private void initConfigFile() {
        try {
            FileReader fileReader = new FileReader("./conf/httpd.conf");
            BufferedReader bufferedReader = new BufferedReader(fileReader);

            String line;
            while ((line = bufferedReader.readLine()) != null) {

                String[] configTokens = line.split(" ");
                String configKey = configTokens[0];
                String configValue = configTokens[1].replaceAll("^\"|\"$", "");

                if (configValue.substring(configValue.length() - 1, configValue.length()).equals("/")) {
                    configValue = configValue.substring(0, configValue.length() - 1);
                }

                if (configKey.equalsIgnoreCase("ScriptAlias") || configKey.equalsIgnoreCase("Alias")) {
                    configValue = configTokens[2].replaceAll("^\"|\"$", "");

                    if (configValue.substring(configValue.length() - 1, configValue.length()).equals("/")) {
                        configValue = configValue.substring(0, configValue.length() - 1);
                    }
                }

                System.out.println("storing configurations...");
                System.out.println("config-key: " + configKey);
                System.out.println("config-value: " + configValue);

                configs.put(configKey, configValue);
            }

            //initialize the port number from the 'Listen' config key
            if (!configs.containsKey("Listen")) {
                this.webServerPort = 8080;
            } else {
                if (!configs.get("Listen").isEmpty()) {
                    this.webServerPort = Integer.parseInt(configs.get("Listen"));
                } else {
                    this.webServerPort = 8080;
                }
            }
        } catch (IOException exception) {
            System.out.println("conf File not found");
            this.webServerPort = 8080;
        }
    }

    @Override
    public void run() {

        initConfigFile();
        initMimeTypes();
        inithtaccessFile();

        try {
            ServerSocket serverSocket = new ServerSocket(webServerPort);
            System.out.println("Opened new socket on port " + webServerPort + "\n");

            while (true) {
                System.out.println("OPENING SOCKET");
                Socket socket = serverSocket.accept();
                System.out.println("Connection accepted from client" + socket);
                WebServerThreads webServerThread = new WebServerThreads(this, socket);
                threadList.add(webServerThread);
                webServerThread.start();
            }
        } catch (IOException exception) {
            System.out.println("Failed to start server");
            System.exit(1);
        }
    }
}

class WebServerThreads extends Thread {

    private WebServer webServer;
    private Socket socket;
    private Map<String, String> passwords = new HashMap<>();

    public WebServerThreads(WebServer webServer, Socket socket) {
        this.webServer = webServer;
        this.socket = socket;
    }

    @Override
    public void run() {
        try {
            readhtpasswdFile();
            processHttpRequests();
        } catch (IOException ex) {
            System.err.println(">> error somewhere");
        }
    }

    //process the various request types
    public void processHttpRequests() throws IOException {
        InputStream inputStream = socket.getInputStream();

        String request = "";
        int nextByte;

        while (inputStream.available() > 0) {
            nextByte = inputStream.read();
            request += (char) (nextByte);
        }

        //log to standard output
        System.out.println("RAW STRING\n" + request);
        
        // log to the log.txt file
        if (Files.exists(Paths.get("./logs/log.txt"))) {
            Files.write(Paths.get("./logs/log.txt"), request.getBytes(), StandardOpenOption.APPEND);
        }
        

        //split the raw request string into the request properties and headers
        String[] requestsLines = request.split("\r\n");
        String[] requestLine = requestsLines[0].split(" ");

        //save the request method type to be used in a switch statement
        String method = requestLine[0];
        String path = requestLine[1];
        String version = requestLine[2];
        String host = requestsLines[1].split(" ")[1];
        String basicAuthToken = "dXNlcm5hbWU6cGFzc3dvcmQ=";

        List<String> headers = new ArrayList<>();
        for (int h = 2; h < requestsLines.length; h++) {
            String header = requestsLines[h];
            if (requestsLines[h].contains("Authorization:")) {
                basicAuthToken = requestsLines[h].split(" ")[2];
                System.out.println("----------------- " + basicAuthToken);
            }
            headers.add(header);
        }

        String accessLog = String.format(" Client: %s\r\n method: %s\r\n path: %s\r\n version: %s\r\n host: %s\r\n headers: %s\r\n",
                socket.toString(), method, path, version, host, headers.toString());
        
        // log to the standard output
        System.out.println(accessLog);
        
        // log to the log.txt file
        if (Files.exists(Paths.get("./logs/log.txt"))) {
            Files.write(Paths.get("./logs/log.txt"), accessLog.getBytes(), StandardOpenOption.APPEND);
        }

        switch (method) {

            //process GET requests by searching the configured webserver paths for the requested resource file
            case "GET":

                //call getFilePath method to return the path of the requested resource
                Path filePath = getFilePath(path);

                //call getContentType method to get the content-type of the requested resource.
                String contentType = getContentType(filePath);
                
                //return a 401 response if user is not authenticated
                if (!isAuthorized(basicAuthToken)) {
                    byte[] unauthorized = "<h1>User unauthorized :(</h1>".getBytes();
                    sendResponse(socket, "401 Unauthorized", contentType, unauthorized);
                }

                //validate the requested resource content-type against the supported webserver content-types
                if (!webServer.getMimeTypes().containsValue(contentType)) {
                    byte[] unsupportedContentType = "<h1>Content-type not supported :(</h1>".getBytes();

                    //return a 404 response if content-type is not supported
                    sendResponse(socket, "400 Bad Request", contentType, unsupportedContentType);
                }

                //validate file existence in the webserver paths 
                if (Files.exists(filePath)) {
                    //return a 200 response if file exists
                    sendResponse(socket, "200 OK", contentType, Files.readAllBytes(filePath));
                } else {
                    // return a 404 if file doesn't exist  
                    byte[] notFoundContent = "<h1>Not found :(</h1>".getBytes();
                    sendResponse(socket, "404 Not Found", "text/html", notFoundContent);
                }
                break;

            //process POST requests by creating specified files in the "ServerRoot" directory path
            case "POST":
             try {
                String postPath = Paths.get(webServer.getConfigs().get("ServerRoot"), path).toString();
                Path postFilePath = Paths.get(webServer.getConfigs().get("ServerRoot"), path);

                File newFile = new File(postPath);
                String postContentType = getContentType(postFilePath);
                
                //return a 401 response if user is not authenticated
                if(!isAuthorized(basicAuthToken)){
                    byte[] unauthorized = "<h1>User unauthorized :(</h1>".getBytes();
                    sendResponse(socket, "401 Unauthorized", postContentType, unauthorized);
                }

                //validate the requested resource content-type against the supported webserver content-types
                if (!webServer.getMimeTypes().containsValue(postContentType)) {
                    byte[] unsupportedContentType = "<h1>Content-type not supported :(</h1>".getBytes();
                    sendResponse(socket, "400 Bad Request", postContentType, unsupportedContentType);
                }

                //create new file in ServerRoot path directory
                if (newFile.createNewFile()) {
                    try {
                        FileWriter myWriter = new FileWriter(postPath);

                        //write the specified "body" content into the created file 
                        myWriter.write(headers.get(headers.size() - 1));
                        myWriter.close();

                        //send a 201 response after creating and writing to the file
                        sendResponse(socket, "201 Created", postContentType, Files.readAllBytes(postFilePath));
                        System.out.println("File created: " + newFile.getName());
                    } catch (IOException e) {
                        //send a 500 Internal Server Error response if file creation error occurs
                        System.out.println("An error occurred.");
                        System.out.println(e.getLocalizedMessage());
                        byte[] internalServerError = "<h1>500 Internal Server Error :(</h1>".getBytes();
                        sendResponse(socket, "500 Internal Server Error", "null", internalServerError);
                    }
                } else {
                    //send a 500 Internal Server Error response if file already exists in ServerRoot path directory
                    System.out.println("File already exists.");
                    byte[] internalServerError = "<h1>500 Internal Server Error: File Already Exists!</h1>".getBytes();
                    sendResponse(socket, "500 Internal Server Error", "null", internalServerError);
                }
            } catch (IOException e) {
                System.out.println("An error occurred.");
                System.out.println(e.getLocalizedMessage());
                byte[] internalServerError = "<h1>500 Internal Server Error :(</h1>".getBytes();
                sendResponse(socket, "500 Internal Server Error", "null", internalServerError);
            }
            break;

            //process HEAD requests by returning content type and size of requested resource file
            case "HEAD":

                Path headFilePath = getFilePath(path);
                String headContentType = getContentType(headFilePath);
                
                //return a 401 response if user is not authenticated
                if (!isAuthorized(basicAuthToken)) {
                    byte[] unauthorized = "<h1>User unauthorized :(</h1>".getBytes();
                    sendResponse(socket, "401 Unauthorized", headContentType, unauthorized);
                }                

                //validate the requested resource content-type against the supported webserver content-types
                if (!webServer.getMimeTypes().containsValue(headContentType)) {
                    byte[] unsupportedContentType = "<h1>Content-type not supported :(</h1>".getBytes();
                    sendResponse(socket, "400 Bad Request", headContentType, unsupportedContentType);
                }
                if (Files.exists(headFilePath)) {
                    //return a 200 response if file exists
                    sendResponse(socket, "200 OK", headContentType, String.valueOf(Files.size(headFilePath)).getBytes());
                } else {
                    //return a 404 response if file doesn't exist
                    byte[] notFoundContent = "<h1>Not found :(</h1>".getBytes();
                    sendResponse(socket, "404 Not Found", "text/html", notFoundContent);
                }
                break;

            //process PUT requests by updating requested resources in the webserver's configured directory paths
            case "PUT":
                Path putFilePath = getFilePath(path);
                String putContentType = getContentType(putFilePath);
                
                //return a 401 response if user is not authenticated
                if (!isAuthorized(basicAuthToken)) {
                    byte[] unauthorized = "<h1>User unauthorized :(</h1>".getBytes();
                    sendResponse(socket, "401 Unauthorized", putContentType, unauthorized);
                }

                //validate the requested resource content-type against the supported webserver content-types
                if (!webServer.getMimeTypes().containsValue(putContentType)) {
                    byte[] unsupportedContentType = "<h1>Content-type not supported :(</h1>".getBytes();
                    sendResponse(socket, "400 Bad Request", putContentType, unsupportedContentType);
                }

                //validate file existence in the webserver paths
                if (Files.exists(putFilePath)) {
                    // write to the requested resource if it exists
                    Files.write(putFilePath, headers.get(headers.size() - 1).getBytes());

                    //return a 201 response and the updated resource file after writing to the reqquested resource 
                    sendResponse(socket, "201 Updated", putContentType, Files.readAllBytes(putFilePath));
                } else {
                    // 404
                    byte[] notFoundContent = "<h1>Not found :(</h1>".getBytes();
                    sendResponse(socket, "404 Not Found", "text/html", notFoundContent);
                }
                break;

            //process DELETE requests by deleting the requested resource if it exists.
            case "DELETE":
                Path deleteFilePath = getFilePath(path);
                String deleteContentType = getContentType(deleteFilePath);
                
                //return a 401 response if user is not authenticated
                if (!isAuthorized(basicAuthToken)) {
                    byte[] unauthorized = "<h1>User unauthorized :(</h1>".getBytes();
                    sendResponse(socket, "401 Unauthorized", deleteContentType, unauthorized);
                }

                //validate the requested resource content-type against the supported webserver content-types
                if (!webServer.getMimeTypes().containsValue(deleteContentType)) {
                    byte[] unsupportedContentType = "<h1>Content-type not supported :(</h1>".getBytes();
                    sendResponse(socket, "400 Bad Request", deleteContentType, unsupportedContentType);
                }
                if (Files.exists(deleteFilePath)) {
                    // delete the requested resource file if it exists
                    if (Files.deleteIfExists(deleteFilePath)) {
                        byte[] deleteResponse = "<h1>File Deleted Successfully</h1>".getBytes();

                        //return a 200 response after deleting the requested resource file
                        sendResponse(socket, "200 OK", deleteContentType, deleteResponse);
                    }

                } else {
                    // return a 404 response if the requested resource file is not found
                    byte[] notFoundContent = "<h1>Not found :(</h1>".getBytes();
                    sendResponse(socket, "404 Not Found", "text/html", notFoundContent);
                }
                break;

            default:

                //return a default 501 response
                byte[] badRequestResponse = "<h1>501 Not Implemented :(</h1>".getBytes();
                sendResponse(socket, "501 Not Implemented", "null", badRequestResponse);
                break;
        }
    }

    //return the content-type of the requested resource file
    private String getContentType(Path filePath) throws IOException {
        return Files.probeContentType(filePath);
    }

    //search the configured webserver paths for the requested resource file
    private Path getFilePath(String path) {
        //redirect to index.html if a resource path is not specified in the request
        if ("/".equals(path)) {
            path = "/index.html";
        }
        if (Files.exists(Paths.get(webServer.getConfigs().get("DocumentRoot"), path))) {
            return Paths.get(webServer.getConfigs().get("DocumentRoot"), path);
        } else if (Files.exists(Paths.get(webServer.getConfigs().get("ScriptAlias"), path))) {
            return Paths.get(webServer.getConfigs().get("ScriptAlias"), path);
        } else if (Files.exists(Paths.get(webServer.getConfigs().get("Alias"), path))) {
            return Paths.get(webServer.getConfigs().get("Alias"), path);
        } else {
            return Paths.get(webServer.getConfigs().get("ServerRoot"), path);
        }
    }

    //send Http Response code to the Client along with the requested content and the content-type
    private void sendResponse(Socket client, String status, String contentType, byte[] content) throws IOException {

        OutputStream clientOutput = client.getOutputStream();
        clientOutput.write(("HTTP/1.1 \r\n" + status).getBytes());
        clientOutput.write("Server: Nusan and Faisal Server\r\n".getBytes());
        clientOutput.write(("Content-Type: " + contentType + "\r\n").getBytes());
        clientOutput.write(("Date: " + LocalDateTime.now() + "\r\n").getBytes());
        clientOutput.write("\r\n".getBytes());
        clientOutput.write(content);
        clientOutput.write("\r\n\r\n".getBytes());
        clientOutput.flush();

//        System.out.println("CLOSING SOCKET");
//        client.close();
    }

    private void readhtpasswdFile() {
        try {
            FileReader fileReader = new FileReader(Paths.get(webServer.getAuthUserFile()).toString());
            BufferedReader bufferedReader = new BufferedReader(fileReader);

            String line;
            while ((line = bufferedReader.readLine()) != null) {
                parseLine(line);
            }
        } catch (IOException exception) {
            System.out.println("htpasswd File not found");
        }
    }

    protected void parseLine(String line) {
        String[] tokens = line.split(":");

        if (tokens.length == 2) {
            passwords.put(tokens[0], tokens[1].replace("{SHA}", "").trim());
        }
    }

    public boolean isAuthorized(String authInfo) {
        // authInfo is provided in the header received from the client
        // as a Base64 encoded string.
        String credentials = new String(
                Base64.getDecoder().decode(authInfo),
                Charset.forName("UTF-8")
        );

        // The string is the key:value pair username:password
        String[] tokens = credentials.split(":");
        return verifyPassword(tokens[0], tokens[1]);
    }

    private boolean verifyPassword(String username, String password) {
        // encrypt the password, and compare it to the password stored
        // in the password file (keyed by username)
        // TODO: implement this - note that the encryption step is provided as a
        // method, below

        String encryptedPassword = encryptClearPassword(password);
        return encryptedPassword.equals(passwords.get(username));
    }

    private String encryptClearPassword(String password) {
        // Encrypt the cleartext password (that was decoded from the Base64 String
        // provided by the client) using the SHA-1 encryption algorithm
        try {
            MessageDigest mDigest = MessageDigest.getInstance("SHA-1");
            byte[] result = mDigest.digest(password.getBytes());

            return Base64.getEncoder().encodeToString(result);
        } catch (Exception e) {
            return "";
        }
    }
}

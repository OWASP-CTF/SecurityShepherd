package servlets;

import com.mongodb.MongoClient;
import dbProcs.Constants;
import dbProcs.Database;
import dbProcs.MongoDatabase;
import dbProcs.Setter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Locale;
import java.util.Properties;
import java.util.ResourceBundle;
import java.util.UUID;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import servlets.module.challenge.XxeChallenge1;
import servlets.module.lesson.XxeLesson;
import utils.Validate;

public class Setup extends HttpServlet {

  private static final Logger log = LogManager.getLogger(Setup.class);
  private static final long serialVersionUID = -892181347446991016L;

  private static volatile Boolean installedCached = null;

  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Translation Stuff
    Locale locale = new Locale(Validate.validateLanguage(request.getSession()));

    ResourceBundle.getBundle("i18n.servlets.errors", locale);
    ResourceBundle bundle = ResourceBundle.getBundle("i18n.text", locale);
    response.setContentType("text/html; charset=UTF-8");
    request.setCharacterEncoding("UTF-8");

    // Output Stuff
    PrintWriter out = response.getWriter();
    String htmlOutput = "";
    boolean success = false;
    boolean validateInput = true;
    boolean saveMysqlProperties = false;
    boolean hasDBFile = false;

    // Parameters From Form
    String dbHost = request.getParameter("dbhost");
    String dbPort = request.getParameter("dbport");
    String dbUser = request.getParameter("dbuser");
    String dbPass = request.getParameter("dbpass");

    // An omitted parameter arrives as null; treat it as "not supplied" rather than dereferencing
    // it. Every one of these is dereferenced further down, and /setup is reachable before
    // authentication, so a missing field has to produce a validation message rather than a 500.
    dbHost = orEmpty(dbHost);
    dbPort = orEmpty(dbPort);
    dbUser = orEmpty(dbUser);
    dbPass = orEmpty(dbPass);

    String dbOptions = null;
    String connectionURL = null;
    String driverType = null;

    String dbOverride = orEmpty(request.getParameter("dboverride"));

    Properties mysql_props = Setup.getDBProps();
    Properties mongo_props = new Properties();

    hasDBFile = (mysql_props != null);

    // Validate host and port up front. Both branches below build "jdbc:mariadb://host:port/" by
    // concatenation and later append "?" + options, so an unvalidated host could smuggle arbitrary
    // JDBC properties into the URL and redirect the connection to a server the requester controls.
    String hostPortError = validateHostPort(dbHost, dbPort);

    if (hostPortError != null) {
      htmlOutput += hostPortError;
      validateInput = false;
      connectionURL = "";
    } else if (hasDBFile) {
      // Db auth file exists, try to load from it

      if (dbHost.isEmpty() && dbPort.isEmpty()) {
        // Both db host and db port are missing, load from props file instead
        connectionURL = mysql_props.getProperty("databaseConnectionURL");
        String databaseSchema = mysql_props.getProperty("databaseSchema");

        if (connectionURL == null || databaseSchema == null) {
          // Nothing useful given in user input or from properties file, bail out.
          validateInput = false;
        }
      } else {
        // Override db properties from request parameters
        connectionURL = "jdbc:mariadb://" + dbHost + ":" + dbPort + "/";

        // Store the overridden data in properties file
        saveMysqlProperties = true;
      }

      dbOptions = mysql_props.getProperty("databaseOptions");
      if (dbOptions == null) {
        dbOptions = "useUnicode=true&character_set_server=utf8mb4";
      }
      driverType = mysql_props.getProperty("DriverType");
      if (driverType == null) {
        driverType = "org.mariadb.jdbc.Driver";
      }
      if (dbUser.isEmpty()) {
        dbUser = mysql_props.getProperty("databaseUsername");
        if (dbUser == null) {
          validateInput = false;
        }
      }
      if (dbPass.isEmpty()) {
        dbPass = mysql_props.getProperty("databasePassword");
        if (dbPass == null) {
          validateInput = false;
        }
      }
    } else if (dbHost.isEmpty()) {
      // There is no properties file to fall back on, so host and port must both be supplied.
      htmlOutput += "Database host and port are required!";
      validateInput = false;
      connectionURL = "";
    } else {
      connectionURL = "jdbc:mariadb://" + dbHost + ":" + dbPort + "/";
      driverType = "org.mariadb.jdbc.Driver";
      dbOptions = "useUnicode=true&character_set_server=utf8mb4";
      validateInput = true;
      saveMysqlProperties = true;
    }

    if (!validateInput) {
      htmlOutput += "Data validation failed.";
      success = false;
    } else {

      String dbAuth = request.getParameter("dbauth");

      String mongodbHost = request.getParameter("mhost");
      String mongodbPort = request.getParameter("mport");
      String nosqlprops =
          new File(Database.class.getResource("/challenges/NoSqlInjection1.properties").getFile())
              .getAbsolutePath();

      try (InputStream mongo_input = new FileInputStream(nosqlprops)) {

        mongo_props.load(mongo_input);
      }

      String mongodbName = mongo_props.getProperty("databaseName");
      if (mongodbName == null) {
        String message = "Could not find databaseName in nosql properties file";
        log.fatal(message);
        throw new RuntimeException(message);
      }

      log.debug("Starting database setup...");

      String auth = null;
      boolean authFileLoaded = false;

      // Both are optional in the documented setup request, and both are dereferenced below, so a
      // caller that omits them must not receive a 500 after the schema has already been written.
      String enableMongoChallenge = orEmpty(request.getParameter("enableMongoChallenge"));

      String enableUnsafeLevels = orEmpty(request.getParameter("unsafeLevels"));

      // Mongo DB properties
      StringBuffer mongoProp = new StringBuffer();
      mongoProp.append("connectionHost=" + mongodbHost);
      mongoProp.append("\n");
      mongoProp.append("connectionPort=" + mongodbPort);
      mongoProp.append("\n");
      mongoProp.append("databaseName=" + mongodbName);
      mongoProp.append("\n");
      mongoProp.append("connectTimeout=10000");
      mongoProp.append("\n");
      mongoProp.append("socketTimeout=0");
      mongoProp.append("\n");
      mongoProp.append("serverSelectionTimeout=30000");
      mongoProp.append("\n");

      try {
        auth =
            new String(Files.readAllBytes(Paths.get(Constants.SETUP_AUTH)), StandardCharsets.UTF_8)
                .trim();
        authFileLoaded = !auth.isEmpty();
      } catch (NoSuchFileException e) {
        // Auth file could not be found.
        htmlOutput += "Auth file could not be found";
        log.error("Auth file could not be found: " + e.toString());
      }

      if (!authFileLoaded) {
        // No auth token available to compare against. This is the normal state on a fresh install,
        // and also on an already-installed instance because a successful install deletes the file
        // (see removeAuthFile). Generate a new token so the operator can read it off disk, but
        // never treat the absent token as a match: doing so would let anyone POST an empty dbauth
        // and re-run the schema, destroying every user and score.
        log.debug("Generating auth file");

        generateAuth();
      }

      if (!isAuthorised(auth, dbAuth)) {
        log.debug("Invalid auth supplied");

        // The supplied auth data was incorrect
        htmlOutput += bundle.getString("generic.text.setup.authentication.failed");
        log.error("Authorization mismatch: the supplied setup token was rejected");

      } else {
        // Test the user's entered database properties. Use DriverManager directly instead of
        // the pool: setup is a one-shot credential check that runs before database.properties
        // exists, and routing it through a pooled DataSource keyed on (url, user) would
        // silently reuse a stale pool when the password changes between setup attempts.
        //
        // Append connectTimeout=5000 so a typo'd host or unreachable port fails fast (matching
        // ConnectionPool's 5s default) instead of hanging on the OS's default TCP connect
        // timeout — DriverManager has no built-in timeout and the setup page would otherwise
        // appear to freeze.
        Boolean connectionSuccess = false;
        log.debug("Attempting to connect to database");

        String testJdbcUrl;
        if (dbOptions != null && !dbOptions.isEmpty()) {
          testJdbcUrl = connectionURL + "?" + dbOptions + "&connectTimeout=5000";
        } else {
          testJdbcUrl = connectionURL + "?connectTimeout=5000";
        }

        try (Connection conn = DriverManager.getConnection(testJdbcUrl, dbUser, dbPass)) {
          connectionSuccess = true;
          log.debug("Database connection successful");

        } catch (SQLException e) {
          // Keep the driver's message out of the response: it leaks internal hostnames, ports,
          // schema names, server versions and the database username. It is logged instead.
          htmlOutput += bundle.getString("generic.text.setup.connection.failed");

          log.error("DB connection error: " + e.toString(), e);
          connectionSuccess = false;
        }

        if (!connectionSuccess) {
          htmlOutput += bundle.getString("generic.text.setup.connection.failed");
        } else {
          // Write the user's entered mysql database properties to file

          if (saveMysqlProperties) {

            try (OutputStream mysql_output = new FileOutputStream(Constants.MYSQL_DB_PROP)) {

              mysql_props = new Properties();

              mysql_props.setProperty("databaseConnectionURL", connectionURL);
              mysql_props.setProperty("DriverType", driverType);
              mysql_props.setProperty("databaseOptions", dbOptions);
              mysql_props.setProperty("databaseSchema", "core");
              mysql_props.setProperty("databaseUsername", dbUser);
              mysql_props.setProperty("databasePassword", dbPass);

              // save properties to project root folder
              mysql_props.store(mysql_output, null);
              success = true;

            } catch (IOException e) {

              success = false;

              htmlOutput = bundle.getString("generic.text.setup.failed");

              log.error("Could not save mysql properties file: " + e.toString(), e);
            }

          } else {
            success = true;
          }

          if (success) {
            // Writing db file succeeded

            try {
              if (dbOverride.equalsIgnoreCase("override")) {
                executeSqlScript();
                htmlOutput =
                    bundle.getString("generic.text.setup.success")
                        + " "
                        + bundle.getString("generic.text.setup.success.overwrittendb");
              } else if (dbOverride.equalsIgnoreCase("upgrade")) {
                executeUpdateScript();
                htmlOutput =
                    bundle.getString("generic.text.setup.success")
                        + " "
                        + bundle.getString("generic.text.setup.success.updatedb");
              } else {
                htmlOutput = bundle.getString("generic.text.setup.success");
              }
              success = true;
            } catch (SQLException e) {
              htmlOutput = bundle.getString("generic.text.setup.failed");
              log.error(bundle.getString("generic.text.setup.failed") + ": " + e.getMessage(), e);
              if (!hasDBFile) {
                FileUtils.deleteQuietly(new File(Constants.MYSQL_DB_PROP));
              }
            }
            // Clean up File as it is not needed anymore. Will Cause a new one to be
            // generated next time too
            removeAuthFile();
            resetInstalledCache();
          }

          if (enableMongoChallenge.equalsIgnoreCase("enable")) {
            if (!Validate.isValidPortNumber(mongodbPort)) {
              htmlOutput = bundle.getString("generic.text.setup.error.valid.port");
              FileUtils.deleteQuietly(new File(Constants.MYSQL_DB_PROP));
            } else {
              Files.write(
                  Paths.get(Constants.MONGO_DB_PROP),
                  mongoProp.toString().getBytes(),
                  StandardOpenOption.CREATE);
              if (MongoDatabase.getMongoDbConnection(null).listDatabaseNames() == null) {
                htmlOutput = bundle.getString("generic.text.setup.connection.mongo.failed");
                if (!hasDBFile) {
                  FileUtils.deleteQuietly(new File(Constants.MYSQL_DB_PROP));
                }
              } else {
                try {
                  executeMongoScript();
                } catch (IOException e) {
                  htmlOutput = bundle.getString("generic.text.setup.failed");
                  log.error("Could not execute mongo script: " + e.toString(), e);
                  if (!hasDBFile) {
                    FileUtils.deleteQuietly(new File(Constants.MYSQL_DB_PROP));
                  }
                }
              }
            }
          }

          if (enableUnsafeLevels.equalsIgnoreCase("enable")) {
            openUnsafeLevels();
            if (!executeCreateChallengeFile()) {
              htmlOutput = bundle.getString("generic.text.setup.file.failed");
              if (!hasDBFile) {
                FileUtils.deleteQuietly(new File(Constants.MYSQL_DB_PROP));
              }
            }
          }
        }
      }
    }
    if (success) {
      htmlOutput =
          "<h2 class=\"title\" id=\"login_title\">"
              + bundle.getString("generic.text.setup.response.success")
              + "</h2><p>"
              + htmlOutput
              + " "
              + bundle.getString("generic.text.setup.response.success.redirecting")
              + "</p>";
    } else {
      log.error("Could not create database...");
      if (!hasDBFile) {
        FileUtils.deleteQuietly(new File(Constants.MYSQL_DB_PROP));
      }
      htmlOutput =
          "<h2 class=\"title\" id=\"login_title\">"
              + bundle.getString("generic.text.setup.response.failed")
              + "</h2><p>"
              + htmlOutput
              + "</p>";
    }
    out.write(htmlOutput);

    out.close();
  }

  /**
   * @param value A request parameter that may be absent
   * @return The value, or the empty string when the parameter was not supplied
   */
  private static String orEmpty(String value) {
    return value == null ? "" : value;
  }

  /**
   * Constant-time comparison of the setup token held on disk against the one supplied in the
   * request. Both must be present; an absent or blank token on either side is never a match.
   *
   * @param expected Token read from the setup auth file, or null when the file was unreadable
   * @param supplied Token supplied by the requester, may be null
   * @return True only when both tokens are present and identical
   */
  static boolean isAuthorised(String expected, String supplied) {
    if (expected == null || expected.isEmpty() || supplied == null) {
      return false;
    }

    String trimmedSupplied = supplied.trim();
    if (trimmedSupplied.isEmpty()) {
      return false;
    }

    return MessageDigest.isEqual(
        expected.getBytes(StandardCharsets.UTF_8),
        trimmedSupplied.getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Validates that db host and port are either both provided or both empty, and that a provided
   * host and port are safe to interpolate into a JDBC URL. Returns null if valid, or an error
   * message if invalid.
   *
   * <p>The host is concatenated straight into "jdbc:mariadb://host:port/" and the options string is
   * appended after a "?", so a host containing "?" or "&" would let a requester append arbitrary
   * JDBC properties (allowLoadLocalInfile, autoDeserialize, ...) and point the connection at a
   * server they control. Restrict it to the characters a hostname, IPv4 address or bracketed IPv6
   * address can legitimately contain.
   */
  static String validateHostPort(String dbHost, String dbPort) {
    if (dbHost == null) dbHost = "";
    if (dbPort == null) dbPort = "";
    if (dbHost.isEmpty() != dbPort.isEmpty()) {
      return "If you override db host and db port, both must be entered!";
    }
    if (dbHost.isEmpty()) {
      // Neither supplied: the caller falls back to the properties file.
      return null;
    }
    if (!isValidDatabaseHost(dbHost)) {
      return "Database host is not a valid hostname or IP address!";
    }
    if (!Validate.isValidPortNumber(dbPort)) {
      return "Database port is not a valid port number!";
    }
    return null;
  }

  /**
   * @param dbHost Candidate database host
   * @return True if the value is a plain hostname, IPv4 address, or bracketed IPv6 address
   */
  private static boolean isValidDatabaseHost(String dbHost) {
    if (dbHost.startsWith("[")) {
      // Bracketed IPv6 literal, e.g. [::1]
      return dbHost.matches("\\[[0-9A-Fa-f:.]{2,45}\\]");
    }
    return dbHost.matches("[A-Za-z0-9]([A-Za-z0-9._-]{0,253}[A-Za-z0-9])?");
  }

  public static boolean isInstalled() {
    Boolean cached = installedCached;
    if (cached != null) {
      return cached;
    }

    synchronized (Setup.class) {
      cached = installedCached;
      if (cached != null) {
        return cached;
      }

      boolean installed = false;

      Properties prop = getDBProps();

      if (prop != null) {
        try (Connection coreConnection = Database.getCoreConnection(null)) {
          if (coreConnection != null) {
            installed = true;
          }
        } catch (SQLException e) {
          log.info("isInstalled got SQL exception " + e.toString() + ", assuming not installed.");
        }
      }

      if (installed) {
        installedCached = true;
      } else {
        generateAuth();
      }

      return installed;
    }
  }

  /** Clear the cached installation status so the next call re-evaluates. */
  public static void resetInstalledCache() {
    installedCached = null;
  }

  public static Properties getDBProps() {

    Properties prop = new Properties();

    // Pull Driver and DB URL out of database.properties

    String mysql_props = Constants.MYSQL_DB_PROP;

    try (InputStream mysql_input = new FileInputStream(mysql_props)) {

      prop.load(mysql_input);

      return prop;

    } catch (IOException e) {
      log.info("Could not load properties file, assuming doesn't exist: " + e.toString());
      return null;
    }
  }

  private static void generateAuth() {
    try {
      boolean tokenNeeded =
          !Files.exists(Paths.get(Constants.SETUP_AUTH), LinkOption.NOFOLLOW_LINKS);

      if (!tokenNeeded) {
        // A file that exists but is blank — an interrupted write, a full disk, a truncated or empty
        // bind-mounted file — would otherwise leave setup permanently unauthorisable: isAuthorised
        // never matches a blank expected token, and this method would keep declining to write one.
        tokenNeeded =
            new String(Files.readAllBytes(Paths.get(Constants.SETUP_AUTH)), StandardCharsets.UTF_8)
                .trim()
                .isEmpty();
        if (tokenNeeded) {
          log.warn("Auth file was empty, regenerating: " + Constants.SETUP_AUTH);
        }
      }

      if (tokenNeeded) {
        UUID randomUUID = UUID.randomUUID();
        log.info("Creating auth file: " + Constants.SETUP_AUTH);

        Files.write(
            Paths.get(Constants.SETUP_AUTH),
            randomUUID.toString().getBytes(StandardCharsets.UTF_8),
            StandardOpenOption.CREATE,
            StandardOpenOption.TRUNCATE_EXISTING);
        log.info("Generated UUID " + randomUUID + " in " + Constants.SETUP_AUTH);
      }
    } catch (IOException e) {
      log.fatal("Unable to generate auth: " + e.getMessage());
      throw new RuntimeException(e);
    }
  }

  private static void removeAuthFile() {
    if (!Files.exists(Paths.get(Constants.SETUP_AUTH), LinkOption.NOFOLLOW_LINKS)) {
      log.info("Could not find " + Constants.SETUP_AUTH);
    } else {
      FileUtils.deleteQuietly(new File(Constants.SETUP_AUTH));
    }
  }

  private synchronized void executeSqlScript() throws IOException, SQLException {

    File file =
        new File(getClass().getClassLoader().getResource("/database/coreSchema.sql").getFile());
    String data = FileUtils.readFileToString(file, Charset.defaultCharset());

    log.debug("Initializing core database");
    try (Connection databaseConnection = Database.getDatabaseConnection(null, true)) {
      try (Statement psProcToexecute = databaseConnection.createStatement()) {
        psProcToexecute.executeUpdate(data);
      }

      file =
          new File(
              getClass().getClassLoader().getResource("/database/moduleSchemas.sql").getFile());
      data = FileUtils.readFileToString(file, Charset.defaultCharset());
      log.debug("Initializing module database");

      try (Statement psProcToexecute = databaseConnection.createStatement()) {
        psProcToexecute.executeUpdate(data);
      }
    }
  }

  private synchronized void executeMongoScript() throws IOException {

    MongoClient mongoConnection = null;

    try {
      File file =
          new File(getClass().getClassLoader().getResource("/mongodb/moduleSchemas.js").getFile());
      mongoConnection = MongoDatabase.getMongoDbConnection(null);
      MongoDatabase.executeMongoScript(file, mongoConnection);
    } catch (IOException e) {
      throw e;
    } finally {
      MongoDatabase.closeConnection(mongoConnection);
    }
  }

  private synchronized void executeUpdateScript() throws IOException, SQLException {

    File file =
        new File(
            getClass().getClassLoader().getResource("/database/updatev3_0tov3_1.sql").getFile());

    String data;

    data = FileUtils.readFileToString(file, Charset.defaultCharset());

    try (Connection databaseConnection = Database.getDatabaseConnection(null, true);
        Statement psProcToexecute = databaseConnection.createStatement()) {
      psProcToexecute.executeUpdate(data);
    }
  }

  private synchronized void openUnsafeLevels() {
    String ApplicationRoot = getServletContext().getRealPath("");
    Setter.openAllModules(ApplicationRoot, true);
  }

  private synchronized Boolean executeCreateChallengeFile() {
    if (XxeLesson.createXxeLessonSolutionFile()
        && XxeChallenge1.createXxeChallenge1SolutionFile()) {
      return true;
    }

    return false;
  }
}

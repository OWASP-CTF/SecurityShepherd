package dbProcs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SetterTest {

  @TempDir Path temporaryDirectory;

  @Test
  void setCoreDatabaseInfo_serializesValuesAsProperties() throws Exception {
    Files.createDirectory(temporaryDirectory.resolve("WEB-INF"));

    assertTrue(
        Setter.setCoreDatabaseInfo(
            temporaryDirectory.toString(),
            "jdbc:mariadb://database:3306/",
            "CaseSensitiveUser",
            "password\nnotAProperty=value"));

    Properties database = load("database.properties");
    assertEquals("jdbc:mariadb://database:3306/", database.getProperty("databaseConnectionURL"));
    assertEquals("org.mariadb.jdbc.Driver", database.getProperty("DriverType"));

    Properties coreDatabase = load("coreDatabase.properties");
    assertEquals("core", coreDatabase.getProperty("databaseConnectionURL"));
    assertEquals("CaseSensitiveUser", coreDatabase.getProperty("databaseUsername"));
    assertEquals("password\nnotAProperty=value", coreDatabase.getProperty("databasePassword"));
    assertNull(coreDatabase.getProperty("notAProperty"));
  }

  private Properties load(String fileName) throws Exception {
    Properties properties = new Properties();
    try (InputStream input =
        Files.newInputStream(temporaryDirectory.resolve("WEB-INF").resolve(fileName))) {
      properties.load(input);
    }
    return properties;
  }
}

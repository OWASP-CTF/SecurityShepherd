package servlets.admin.config;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class ChangeCoreDatabaseTest {

  @Test
  void databaseConfiguration_requiresCompleteMariaDbConfiguration() {
    assertTrue(
        ChangeCoreDatabase.isValidDatabaseConfiguration(
            "jdbc:mariadb://database:3306/", "shepherd", "correct horse battery staple"));

    assertFalse(
        ChangeCoreDatabase.isValidDatabaseConfiguration(
            "", "shepherd", "correct horse battery staple"));
    assertFalse(
        ChangeCoreDatabase.isValidDatabaseConfiguration(
            "jdbc:postgresql://database:5432/", "shepherd", "correct horse battery staple"));
    assertFalse(
        ChangeCoreDatabase.isValidDatabaseConfiguration(
            "jdbc:mariadb://database:3306/", "", "correct horse battery staple"));
    assertFalse(
        ChangeCoreDatabase.isValidDatabaseConfiguration(
            "jdbc:mariadb://database:3306/", "shepherd", ""));
  }

  @Test
  void databaseConfiguration_rejectsPropertyInjectionCharacters() {
    assertFalse(
        ChangeCoreDatabase.isValidDatabaseConfiguration(
            "jdbc:mariadb://database:3306/\ndatabasePassword=attacker", "shepherd", "password"));
    assertFalse(
        ChangeCoreDatabase.isValidDatabaseConfiguration(
            "jdbc:mariadb://database:3306/", "shepherd\rDriverType=evil", "password"));
    assertFalse(
        ChangeCoreDatabase.isValidDatabaseConfiguration(
            "jdbc:mariadb://database:3306/", "shepherd", "password\u0000extra"));
  }
}

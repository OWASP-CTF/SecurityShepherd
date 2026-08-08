package servlets.admin.moduleManagement;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class AdminModuleInputValidationTest {

  @Test
  void categorySelection_isBoundedAndRejectsControlCharacters() {
    assertTrue(OpenOrCloseByCategory.validCategories(new String[] {"Injection", "Crypto"}));
    assertFalse(OpenOrCloseByCategory.validCategories(null));
    assertFalse(OpenOrCloseByCategory.validCategories(new String[0]));
    assertFalse(OpenOrCloseByCategory.validCategories(new String[] {"Injection\r\nforged"}));
    assertFalse(OpenOrCloseByCategory.validCategories(new String[101]));
  }

  @Test
  void moduleSelection_isBoundedAndRejectsControlCharacters() {
    assertTrue(SetModuleStatus.validModuleIds(new String[] {"module-1", "module-2"}));
    assertFalse(SetModuleStatus.validModuleIds(null));
    assertFalse(SetModuleStatus.validModuleIds(new String[0]));
    assertFalse(SetModuleStatus.validModuleIds(new String[] {null}));
    assertFalse(SetModuleStatus.validModuleIds(new String[] {"module-1\nmodule-2"}));
    assertFalse(SetModuleStatus.validModuleIds(new String[1001]));
  }
}

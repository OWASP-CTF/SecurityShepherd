package utils;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class ModulePlanTest {

  @AfterEach
  void resetLayout() throws ReflectiveOperationException {
    ModulePlan.applyModuleLayout("ctf");
    Field isLoaded = ModulePlan.class.getDeclaredField("isLoaded");
    isLoaded.setAccessible(true);
    isLoaded.setBoolean(null, false);
  }

  @Test
  void openLayoutEnablesOnlyOpenFloor() throws ReflectiveOperationException {
    ModulePlan.applyModuleLayout("open");
    Field isLoaded = ModulePlan.class.getDeclaredField("isLoaded");
    isLoaded.setAccessible(true);
    isLoaded.setBoolean(null, true);

    assertTrue(ModulePlan.isOpenFloor());
    assertFalse(ModulePlan.isIncrementalFloor());
    assertFalse(ModulePlan.isTournamentFloor());
  }
}

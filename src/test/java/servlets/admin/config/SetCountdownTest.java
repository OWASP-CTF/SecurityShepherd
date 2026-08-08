package servlets.admin.config;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.LocalDateTime;
import javax.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

class SetCountdownTest {

  @Test
  void requestedTimes_readsEachIndependentParameter() {
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getParameter("startTime")).thenReturn("2026-08-08T10:00:00");
    when(request.getParameter("lockTime")).thenReturn("2026-08-08T11:00:00");
    when(request.getParameter("endTime")).thenReturn("2026-08-08T12:00:00");

    assertArrayEquals(
        new LocalDateTime[] {
          LocalDateTime.parse("2026-08-08T10:00:00"),
          LocalDateTime.parse("2026-08-08T11:00:00"),
          LocalDateTime.parse("2026-08-08T12:00:00")
        },
        SetCountdown.requestedTimes(request));
  }
}

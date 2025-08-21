Perfect 👍 I’ll give you the **full working code** for all custom exceptions + `GlobalExceptionHandler`.
Each custom exception will extend `RuntimeException` so they are **unchecked** and don’t clutter your service code with `throws`.

---

### 📌 Custom Exceptions

```java
// src/main/java/org/godigit/policyvault/exception/PolicyNotFoundException.java
package org.godigit.policyvault.exception;

public class PolicyNotFoundException extends RuntimeException {
    public PolicyNotFoundException(String message) {
        super(message);
    }
}
```

```java
// src/main/java/org/godigit/policyvault/exception/UserNotFoundException.java
package org.godigit.policyvault.exception;

public class UserNotFoundException extends RuntimeException {
    public UserNotFoundException(String message) {
        super(message);
    }
}
```

```java
// src/main/java/org/godigit/policyvault/exception/UnauthorizedActionException.java
package org.godigit.policyvault.exception;

public class UnauthorizedActionException extends RuntimeException {
    public UnauthorizedActionException(String message) {
        super(message);
    }
}
```

```java
// src/main/java/org/godigit/policyvault/exception/DuplicatePolicyException.java
package org.godigit.policyvault.exception;

public class DuplicatePolicyException extends RuntimeException {
    public DuplicatePolicyException(String message) {
        super(message);
    }
}
```

```java
// src/main/java/org/godigit/policyvault/exception/InvalidRequestException.java
package org.godigit.policyvault.exception;

public class InvalidRequestException extends RuntimeException {
    public InvalidRequestException(String message) {
        super(message);
    }
}
```

---

### 📌 Global Exception Handler

```java
// src/main/java/org/godigit/policyvault/exception/GlobalExceptionHandler.java
package org.godigit.policyvault.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
public class GlobalExceptionHandler {

    private ResponseEntity<Object> buildResponse(HttpStatus status, String message) {
        Map<String, Object> body = new HashMap<>();
        body.put("timestamp", Instant.now());
        body.put("status", status.value());
        body.put("error", status.getReasonPhrase());
        body.put("message", message);
        return new ResponseEntity<>(body, status);
    }

    @ExceptionHandler(PolicyNotFoundException.class)
    public ResponseEntity<Object> handlePolicyNotFound(PolicyNotFoundException ex) {
        return buildResponse(HttpStatus.NOT_FOUND, ex.getMessage());
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<Object> handleUserNotFound(UserNotFoundException ex) {
        return buildResponse(HttpStatus.NOT_FOUND, ex.getMessage());
    }

    @ExceptionHandler(UnauthorizedActionException.class)
    public ResponseEntity<Object> handleUnauthorized(UnauthorizedActionException ex) {
        return buildResponse(HttpStatus.FORBIDDEN, ex.getMessage());
    }

    @ExceptionHandler(DuplicatePolicyException.class)
    public ResponseEntity<Object> handleDuplicatePolicy(DuplicatePolicyException ex) {
        return buildResponse(HttpStatus.CONFLICT, ex.getMessage());
    }

    @ExceptionHandler(InvalidRequestException.class)
    public ResponseEntity<Object> handleInvalidRequest(InvalidRequestException ex) {
        return buildResponse(HttpStatus.BAD_REQUEST, ex.getMessage());
    }

    @ExceptionHandler(Exception.class) // fallback for unexpected errors
    public ResponseEntity<Object> handleGeneral(Exception ex) {
        return buildResponse(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred: " + ex.getMessage());
    }
}
```

---

✅ Now you have **5 custom exceptions** + **GlobalExceptionHandler**.
Whenever you `throw new PolicyNotFoundException("Policy not found with id: ...")`, the user will get a clean JSON response like:

```json
{
  "timestamp": "2025-08-21T17:40:32.123Z",
  "status": 404,
  "error": "Not Found",
  "message": "Policy not found with id: abc123"
}
```

---

Do you want me to now **integrate these exceptions into your service implementation classes** (like `AuditLogServiceImpl`, `PolicyVersionServiceImpl`, etc.) so they start throwing the right exception instead of crashing?

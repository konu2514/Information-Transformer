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



package org.godigit.policyvault.service.impl;

import org.godigit.policyvault.entities.AuditLog;
import org.godigit.policyvault.entities.Policy;
import org.godigit.policyvault.exception.PolicyNotFoundException;
import org.godigit.policyvault.exception.UserNotFoundException;
import org.godigit.policyvault.repository.AuditLogRepository;
import org.godigit.policyvault.repository.PolicyRepository;
import org.godigit.policyvault.service.AuditLogService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
public class AuditLogServiceImpl implements AuditLogService {

    private final AuditLogRepository auditLogRepo;
    private final PolicyRepository policyRepository;

    public AuditLogServiceImpl(AuditLogRepository auditLogRepo, PolicyRepository policyRepository) {
        this.auditLogRepo = auditLogRepo;
        this.policyRepository = policyRepository;
    }

    @Override
    public void log(String userId, UUID policyId, String action) {
        // Check if the policy exists before logging
        Policy policy = policyRepository.findById(policyId)
                .orElseThrow(() -> new PolicyNotFoundException("Policy with ID " + policyId + " not found"));

        if (userId == null || userId.trim().isEmpty()) {
            throw new UserNotFoundException("User ID cannot be null or empty");
        }

        AuditLog log = new AuditLog();
        log.setUserId(userId);
        log.setPolicy(policy);
        log.setAction(action);
        auditLogRepo.save(log);
    }

    @Override
    @PreAuthorize("hasRole('ADMIN')")
    public List<AuditLog> getLogsByPolicy(UUID policyId) {
        // Validate policy existence
        if (!policyRepository.existsById(policyId)) {
            throw new PolicyNotFoundException("Policy with ID " + policyId + " not found");
        }

        return auditLogRepo.findByPolicyId(policyId);
    }

    @Override
    @PreAuthorize("hasRole('ADMIN')")
    public List<AuditLog> getLogsByUser(String userId) {
        if (userId == null || userId.trim().isEmpty()) {
            throw new UserNotFoundException("User ID cannot be null or empty");
        }

        List<AuditLog> logs = auditLogRepo.findByUserId(userId);
        if (logs.isEmpty()) {
            throw new UserNotFoundException("No logs found for user ID: " + userId);
        }
        return logs;
    }

    @Override
    public void record(String userId, UUID policyId, String action, String description, Instant ts) {
        // Policy validation
        Policy policy = policyRepository.findById(policyId)
                .orElseThrow(() -> new PolicyNotFoundException("Policy with ID " + policyId + " not found"));

        if (userId == null || userId.trim().isEmpty()) {
            throw new UserNotFoundException("User ID cannot be null or empty");
        }

        AuditLog log = new AuditLog();
        log.setUserId(userId);
        log.setPolicy(policy);
        log.setAction(action);
        log.setDescription(description);
        log.setTimestamp(ts != null ? ts : Instant.now()); // default to current time
        auditLogRepo.save(log);
    }
}



package org.godigit.policyvault.service.impl;

import org.godigit.policyvault.dto.ChangeLogResponse;
import org.godigit.policyvault.entities.ChangeLog;
import org.godigit.policyvault.exception.PolicyNotFoundException;
import org.godigit.policyvault.exception.ResourceNotFoundException;
import org.godigit.policyvault.repository.ChangeLogRepository;
import org.godigit.policyvault.repository.PolicyRepository;
import org.godigit.policyvault.service.ChangeLogService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
public class ChangeLogServiceImpl implements ChangeLogService {

    private final ChangeLogRepository changeLogRepo;
    private final PolicyRepository policyRepository;

    public ChangeLogServiceImpl(ChangeLogRepository changeLogRepo, PolicyRepository policyRepository) {
        this.changeLogRepo = changeLogRepo;
        this.policyRepository = policyRepository;
    }

    @Override
    @PreAuthorize("hasAnyRole('COMPLIANCE_OFFICER','ADMIN')")
    public List<ChangeLogResponse> getChangeLogs(UUID policyId) {
        // Validate policy existence
        if (!policyRepository.existsById(policyId)) {
            throw new PolicyNotFoundException("Policy with ID " + policyId + " not found");
        }

        // Fetch logs
        List<ChangeLog> logs = changeLogRepo.findByPolicyId(policyId);
        if (logs.isEmpty()) {
            throw new ResourceNotFoundException("No change logs found for policy ID: " + policyId);
        }

        // Convert entity to DTO
        return logs.stream()
                .map(cl -> new ChangeLogResponse(
                        cl.getId(),
                        cl.getPolicy().getId(),
                        cl.getOldVersion(),
                        cl.getNewVersion(),
                        cl.getChangedBy(),
                        cl.getDescription(),
                        cl.getChangeDate()
                ))
                .toList();
    }
}



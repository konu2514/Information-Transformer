Absolutely—I understand what you want:

1. quick sanity-check of the latest project you uploaded, and
2. a clear, step-by-step implementation of a **Department Head notification** feature, with **full, paste-ready code** and comments.

I don’t need anything else from you right now—let’s do it.

---

# What I noticed in your latest project (very briefly)

* I still see literal `...` placeholders in multiple files (e.g., `Users.java`, `PolicyServiceImpl.java`, `SecurityConfig.java`). These **won’t compile**. Replace all `...` with real code.
* Your roles are an **enum with `ROLE_` prefix**:

  ```java
  public enum Role { ROLE_ADMIN, ROLE_COMPLIANCE_OFFICER, ROLE_DEPT_HEAD, ROLE_EMPLOYEE }
  ```

  When you use `hasRole('X')`, Spring will look for **`ROLE_X`**. So use `hasRole('DEPT_HEAD')`, `hasRole('ADMIN')`, etc. (No `ROLE_` in the annotation.)
* Make your role usage consistent: use **`DEPT_HEAD`** (not `DEPARTMENT_HEAD`) everywhere.
* Your endpoints mix `/policies` and `/api/...` in security—make sure your `SecurityConfig` patterns actually match your controller paths.

Those are just heads-ups so you don’t run into invisible bugs while adding notifications.

---

# Goal of the new feature

When a policy is **created** or **updated**, notify the **Department Head** of that policy’s department.
Dept Heads can fetch their notifications (and mark them as read).

We’ll add:

* `Notification` entity + repository
* `NotificationService` (+ impl)
* `NotificationController` endpoints
* Small changes in `UserRepository` and `PolicyServiceImpl` to **trigger notifications**

> I’ll assume your `Users` entity has a `department` field (string) and that Dept Heads are users with role `ROLE_DEPT_HEAD`. If your `roles` mapping is a `Set<Role>`, make sure it’s annotated as an **ElementCollection** (I include the correct mapping below).

---

## 1) Entity: `Notification`

**File:** `src/main/java/org/godigit/policyvault/entities/Notification.java`

```java
package org.godigit.policyvault.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

/**
 * Stores a single user notification (e.g., "Policy X was updated").
 */
@Entity
@Getter @Setter
@Table(name = "notifications", indexes = {
        @Index(name = "idx_notifications_recipient", columnList = "recipient_id"),
        @Index(name = "idx_notifications_created_at", columnList = "createdAt")
})
public class Notification {

    @Id
    @GeneratedValue
    private UUID id;

    @Column(nullable = false, length = 300)
    private String message;

    @Column(nullable = false)
    private boolean readFlag = false;

    @Column(nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    /**
     * Who receives this notification (the Dept Head).
     */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "recipient_id", nullable = false,
            foreignKey = @ForeignKey(name = "fk_notification_recipient"))
    private Users recipient;

    /**
     * Optional link to a policy this notification refers to (helpful for UIs).
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "policy_id", foreignKey = @ForeignKey(name = "fk_notification_policy"))
    private Policy policy;

    /**
     * Store department snapshot (string). Useful for filtering without joins.
     */
    @Column(length = 80)
    private String department;
}
```

---

## 2) Repository: `NotificationRepository`

**File:** `src/main/java/org/godigit/policyvault/repository/NotificationRepository.java`

```java
package org.godigit.policyvault.repository;

import org.godigit.policyvault.entities.Notification;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface NotificationRepository extends JpaRepository<Notification, UUID> {

    // List for a user (order newest first)
    List<Notification> findByRecipientUsernameOrderByCreatedAtDesc(String username);

    // Unread count for a user
    int countByRecipientUsernameAndReadFlagIsFalse(String username);

    // Fetch ensuring the notification belongs to the user
    Optional<Notification> findByIdAndRecipientUsername(UUID id, String username);
}
```

---

## 3) (Important) Fix/Confirm `Users.roles` mapping (ElementCollection)

If your `Users` entity currently has:

```java
@Enumerated(EnumType.STRING)
@Column(name = "role", nullable=false, length=40)
private Set<Role> roles = new HashSet<>();
```

That’s **invalid** for a collection. Replace with:

```java
@ElementCollection(fetch = FetchType.EAGER)            // <-- collection of enums
@CollectionTable(
        name = "user_roles",
        joinColumns = @JoinColumn(name = "user_id",
                foreignKey = @ForeignKey(name = "fk_user_roles_user"))
)
@Enumerated(EnumType.STRING)
@Column(name = "role", length = 40, nullable = false)
private Set<Role> roles = new java.util.HashSet<>();
```

This will create a separate `user_roles` table and make repository queries on roles work.

---

## 4) Repository: add a method to find Dept Head by department

**File:** `src/main/java/org/godigit/policyvault/repository/UserRepository.java`
(Add this method)

```java
import org.godigit.policyvault.entities.Role;
// ...

// One Dept Head for a department (adjust to findAll... if you want multiple heads)
java.util.Optional<org.godigit.policyvault.entities.Users>
findFirstByDepartmentAndRolesContaining(String department, Role role);
```

> Because `roles` is a collection of enums, Spring Data supports `Containing` for collection membership.

---

## 5) DTO: `NotificationDto` (simple API shape)

**File:** `src/main/java/org/godigit/policyvault/dto/NotificationDto.java`

```java
package org.godigit.policyvault.dto;

import java.time.Instant;
import java.util.UUID;

public record NotificationDto(
        UUID id,
        String message,
        boolean read,
        Instant createdAt,
        UUID policyId,
        String department
) {}
```

---

## 6) Service interface: `NotificationService`

**File:** `src/main/java/org/godigit/policyvault/service/NotificationService.java`

```java
package org.godigit.policyvault.service;

import org.godigit.policyvault.dto.NotificationDto;
import org.godigit.policyvault.entities.Policy;
import org.godigit.policyvault.entities.Users;
import org.springframework.security.access.prepost.PreAuthorize;

import java.util.List;
import java.util.UUID;

public interface NotificationService {

    /**
     * Create a simple notification for a user.
     */
    void notifyUser(Users user, String message, Policy policy, String department);

    /**
     * Find the dept head for the given department and notify them.
     * (Called from PolicyService when creating/updating policies)
     */
    void notifyDeptHead(String department, String message, Policy policy);

    /**
     * Get notifications for the currently authenticated user (by username).
     */
    @PreAuthorize("isAuthenticated()")
    List<NotificationDto> getMyNotifications(String username);

    /**
     * Number of unread notifications for the authenticated user.
     */
    @PreAuthorize("isAuthenticated()")
    int getMyUnreadCount(String username);

    /**
     * Mark one notification as read (must belong to the user).
     */
    @PreAuthorize("isAuthenticated()")
    void markAsRead(UUID id, String username);

    /**
     * Admin utility: fetch notifications for any user.
     */
    @PreAuthorize("hasRole('ADMIN')")
    List<NotificationDto> getForUser(String username);
}
```

---

## 7) Service implementation: `NotificationServiceImpl`

**File:** `src/main/java/org/godigit/policyvault/service/impl/NotificationServiceImpl.java`

```java
package org.godigit.policyvault.service.impl;

import org.godigit.policyvault.dto.NotificationDto;
import org.godigit.policyvault.entities.Notification;
import org.godigit.policyvault.entities.Policy;
import org.godigit.policyvault.entities.Role;
import org.godigit.policyvault.entities.Users;
import org.godigit.policyvault.repository.NotificationRepository;
import org.godigit.policyvault.repository.UserRepository;
import org.godigit.policyvault.service.NotificationService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Service
@Transactional
public class NotificationServiceImpl implements NotificationService {

    private final NotificationRepository notificationRepo;
    private final UserRepository userRepo;

    public NotificationServiceImpl(NotificationRepository notificationRepo,
                                   UserRepository userRepo) {
        this.notificationRepo = notificationRepo;
        this.userRepo = userRepo;
    }

    @Override
    public void notifyUser(Users user, String message, Policy policy, String department) {
        Notification n = new Notification();
        n.setRecipient(user);
        n.setMessage(message);
        n.setPolicy(policy);
        n.setDepartment(department);
        notificationRepo.save(n);
    }

    @Override
    public void notifyDeptHead(String department, String message, Policy policy) {
        userRepo.findFirstByDepartmentAndRolesContaining(department, Role.ROLE_DEPT_HEAD)
                .ifPresent(head -> notifyUser(head, message, policy, department));
        // If no head found, we silently skip. You can log or fallback to ADMINs if you like.
    }

    @Override
    public List<NotificationDto> getMyNotifications(String username) {
        return notificationRepo.findByRecipientUsernameOrderByCreatedAtDesc(username)
                .stream()
                .map(n -> new NotificationDto(
                        n.getId(),
                        n.getMessage(),
                        n.isReadFlag(),
                        n.getCreatedAt(),
                        n.getPolicy() != null ? n.getPolicy().getId() : null,
                        n.getDepartment()
                ))
                .toList();
    }

    @Override
    public int getMyUnreadCount(String username) {
        return notificationRepo.countByRecipientUsernameAndReadFlagIsFalse(username);
    }

    @Override
    public void markAsRead(UUID id, String username) {
        // Only allow marking the user's own notification
        var n = notificationRepo.findByIdAndRecipientUsername(id, username)
                .orElseThrow(() -> new IllegalArgumentException("Notification not found or does not belong to user"));
        if (!n.isReadFlag()) {
            n.setReadFlag(true);
            notificationRepo.save(n);
        }
    }

    @Override
    public List<NotificationDto> getForUser(String username) {
        return notificationRepo.findByRecipientUsernameOrderByCreatedAtDesc(username)
                .stream()
                .map(n -> new NotificationDto(
                        n.getId(),
                        n.getMessage(),
                        n.isReadFlag(),
                        n.getCreatedAt(),
                        n.getPolicy() != null ? n.getPolicy().getId() : null,
                        n.getDepartment()
                ))
                .toList();
    }
}
```

---

## 8) Controller: `NotificationController`

**File:** `src/main/java/org/godigit/policyvault/controller/NotificationController.java`

```java
package org.godigit.policyvault.controller;

import org.godigit.policyvault.dto.NotificationDto;
import org.godigit.policyvault.service.NotificationService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * Endpoints for Dept Heads (and any user) to view notifications.
 */
@RestController
@RequestMapping("/notifications")
public class NotificationController {

    private final NotificationService notifications;

    public NotificationController(NotificationService notifications) {
        this.notifications = notifications;
    }

    /**
     * Get my notifications (authenticated user).
     */
    @GetMapping("/my")
    public ResponseEntity<List<NotificationDto>> myNotifications(Authentication auth) {
        return ResponseEntity.ok(notifications.getMyNotifications(auth.getName()));
    }

    /**
     * Get my unread count.
     */
    @GetMapping("/my/unread-count")
    public ResponseEntity<Integer> unreadCount(Authentication auth) {
        return ResponseEntity.ok(notifications.getMyUnreadCount(auth.getName()));
    }

    /**
     * Mark one of my notifications as read.
     */
    @PatchMapping("/{id}/read")
    public ResponseEntity<Void> markRead(@PathVariable UUID id, Authentication auth) {
        notifications.markAsRead(id, auth.getName());
        return ResponseEntity.noContent().build();
    }

    /**
     * Admin: fetch someone else's notifications.
     */
    @GetMapping("/user/{username}")
    public ResponseEntity<List<NotificationDto>> forUser(@PathVariable String username) {
        return ResponseEntity.ok(notifications.getForUser(username));
    }
}
```

> Because you’re enforcing access mainly in the **service** layer with `@PreAuthorize`, I didn’t add controller-level annotations. If you prefer controller-level checks, I can add them.

---

## 9) Trigger notifications from policy actions

Modify your **`PolicyServiceImpl`**:

* Inject `NotificationService`
* After **create** and **update**, call `notifyDeptHead(...)`

**File:** `src/main/java/org/godigit/policyvault/service/impl/PolicyServiceImpl.java`
(Only the relevant diffs are shown below—keep your existing logic as-is.)

```java
// imports
import org.godigit.policyvault.service.NotificationService;

// class fields
private final NotificationService notificationService;

// constructor
public PolicyServiceImpl(PolicyRepository policyRepo,
                         PolicyVersionRepository versionRepo,
                         ChangeLogRepository changeLogRepo,
                         NotificationService notificationService) {
    this.policyRepo = policyRepo;
    this.versionRepo = versionRepo;
    this.changeLogRepo = changeLogRepo;
    this.notificationService = notificationService;
}
```

**After create policy:**

```java
// After you save 'policy' and 'version'
notificationService.notifyDeptHead(
        policy.getDepartment(),
        "A new policy \"" + policy.getTitle() + "\" was created in " + policy.getDepartment(),
        policy
);
```

**After update policy:**

```java
// After you save the new version and changelog, and update policy version number
notificationService.notifyDeptHead(
        policy.getDepartment(),
        "Policy \"" + policy.getTitle() + "\" was updated to v" + newVersion + " in " + policy.getDepartment(),
        policy
);
```

> If your `Policy` entity stores department as a `String` (e.g., `"Finance"`), this will work.
> If you later introduce a `Department` entity, we can update the references cleanly.

---

## 10) (Optional) Security config route

If your security config uses ant matchers, ensure **`/notifications/**` is authenticated**:

```java
// In SecurityConfig where you authorize requests
.requestMatchers("/auth/**").permitAll()
.requestMatchers("/notifications/**").authenticated()
// you can tighten admin-only endpoints if you later move checks to controllers
.anyRequest().authenticated()
```

(Your method security in `NotificationService` already restricts who can see what.)

---

## 11) How to test (Insomnia/Postman)

1. **Create or update a policy** (as COMPLIANCE\_OFFICER or ADMIN).
   That will trigger notifications to the **Dept Head** of that policy’s department.

2. Login as the dept head, get your token, then call:

* `GET /notifications/my` → should list your notifications (newest first)
* `GET /notifications/my/unread-count` → integer count
* `PATCH /notifications/{id}/read` → marks a notification as read (204 No Content)

If you want to preview quickly, you can temporarily add:

* `GET /notifications/user/{username}` as ADMIN and see other users’ notifications.

---

## That’s it 🎯

* You now have a **DB-backed notification system**.
* Notifications are **created automatically** on policy create/update.
* Dept Heads can **fetch & mark as read**.
* Access is enforced in the **service layer** (consistent with your current approach).

If you want email or realtime (WebSocket) delivery later, we can layer it on top of this foundation without changing your business logic.

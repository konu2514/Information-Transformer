I’m all set—no blocking questions. I unpacked your zip and reviewed the project structure/class files. Here’s a clear, actionable review with fixes.

---

# 🚨 High-priority issues to fix

1. **Controllers vs Security URL mismatch (will block access)**

* Your `SecurityConfig` protects `/api/policies/**`, but `PolicyController` is mapped to `@RequestMapping("/policies")`.
* **Fix (pick one):**

  * EITHER: Change controllers to start with `/api/...`:

    ```java
    @RestController
    @RequestMapping("/api/policies")
    public class PolicyController { ... }
    ```
  * OR: Change SecurityConfig matchers to `"/policies/**"` instead of `"/api/policies/**"`.

2. **Source files contain literal `...` placeholders (won’t compile)**

* I found `...` directly inside source for key classes (e.g., `SecurityConfig.java`, `JwtAuthFilter.java`, `JwtUtils.java`, `AuthController.java`, `PolicyController.java`, `PolicyServiceImpl.java`). That’s **invalid Java** and will break build/startup.
* **Fix:** Replace the `...` blocks with real code. If you want, I can paste complete, ready-to-compile versions for these classes.

3. **User–Role relationship still Many-to-Many (but you asked for single role)**

* `entities/User.java` currently:

  ```java
  @ManyToMany(fetch = FetchType.EAGER)
  @JoinTable(name="user_roles", ...)
  private Set<Role> roles;
  ```
* This creates the `user_roles` join table (which you observed) and allows multiple roles per user.
* **Fix (single role):**

  * Change to:

    ```java
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "role_id", nullable = false)
    private Role role;
    ```
  * Update dependent code:

    * `UserPrincipal` → build authorities from a **single** role, not a set.
    * `CustomUserDetailsService` and `AuthController` → set/get `user.getRole()` instead of `getRoles()`.
  * Drop the join table (JPA will manage schema if `ddl-auto=update`; otherwise migrate).

4. **`AuthController` is incomplete and uses query params for auth**

* The file currently contains `...` and uses `@RequestParam` for username/password and hardcodes `ROLE_EMPLOYEE`.
* **Fix:**

  * Replace with a proper DTO-based controller that:

    * Exposes `POST /api/auth/register` (admin or open, your choice).
    * Exposes `POST /api/auth/login` returning JSON `{ "token": "..." }`.
    * Sets the **single** `Role` on the `User` (`user.setRole(role)`), not a `Set<Role>`.

5. **SecurityConfig shows only partial code (ellipsis)**

* I can see your request matchers, but crucial parts are truncated.
* **Fix:** Ensure it has a full `SecurityFilterChain` bean **and** adds the JWT filter:

  ```java
  http.csrf(csrf -> csrf.disable())
      .authorizeHttpRequests(auth -> auth
          .requestMatchers("/api/auth/**").permitAll()
          .requestMatchers("/api/admin/**").hasRole("ADMIN")
          .requestMatchers("/api/policies/**").hasAnyRole("EMPLOYEE","DEPARTMENT_HEAD","COMPLIANCE_OFFICER","ADMIN")
          .anyRequest().authenticated()
      )
      .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
  ```

---

# ✅ Medium-priority cleanups

6. **Rename stray class `search/serch.java`**

* File: `src/main/java/org/godigit/policyvault/search/serch.java` (empty, misspelled).
* **Fix:** Delete or rename to `Search.java` if you plan to use it.

7. **Return JSON consistently from auth**

* `AuthController#login` currently returns a raw token string. It’s better to return JSON for clients:

  ```java
  record JwtResponse(String token) {}
  return new JwtResponse(jwtUtils.generateToken(username));
  ```

8. **Optional CORS**

* If a frontend will call the API locally, add:

  ```java
  @Bean
  CorsConfigurationSource corsConfigurationSource() {
      var cors = new CorsConfiguration();
      cors.setAllowedOrigins(List.of("http://localhost:3000"));
      cors.setAllowedMethods(List.of("GET","POST","PUT","DELETE","OPTIONS"));
      cors.setAllowedHeaders(List.of("*"));
      var source = new UrlBasedCorsConfigurationSource();
      source.registerCorsConfiguration("/**", cors);
      return source;
  }
  ```

  and in the chain: `.cors(Customizer.withDefaults())`.

9. **Validation annotations**

* For your DTOs (e.g., register/login), add `@NotBlank` etc., and use `@Valid` in controller methods to get automatic 400s on bad input.

---

# 🔧 Concrete code you can paste

## A) `User` (single role)

```java
package org.godigit.policyvault.entities;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
@Table(name = "users")
public class User {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable=false, length=80)
    private String username;

    @Column(nullable=false)
    private String password;

    @Column(length=120)
    private String email;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "role_id", nullable=false)
    private Role role;
}
```

## B) `UserPrincipal` (single role)

```java
package org.godigit.policyvault.security;

import lombok.AllArgsConstructor;
import org.godigit.policyvault.entities.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@AllArgsConstructor
public class UserPrincipal implements UserDetails {
    private final User user;

    public static UserPrincipal build(User user) { return new UserPrincipal(user); }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(user.getRole().getName()));
    }
    @Override public String getPassword() { return user.getPassword(); }
    @Override public String getUsername() { return user.getUsername(); }
    @Override public boolean isAccountNonExpired() { return true; }
    @Override public boolean isAccountNonLocked() { return true; }
    @Override public boolean isCredentialsNonExpired() { return true; }
    @Override public boolean isEnabled() { return true; }
}
```

## C) `CustomUserDetailsService` (unchanged logic, maps single role via UserPrincipal)

```java
package org.godigit.policyvault.service.impl;

import org.godigit.policyvault.entities.User;
import org.godigit.policyvault.repository.UserRepository;
import org.godigit.policyvault.security.UserPrincipal;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;
    public CustomUserDetailsService(UserRepository userRepository) { this.userRepository = userRepository; }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        return UserPrincipal.build(user);
    }
}
```

## D) `AuthController` (replace `...`, use JSON DTOs, single role)

```java
package org.godigit.policyvault.controller;

import lombok.RequiredArgsConstructor;
import org.godigit.policyvault.entities.Role;
import org.godigit.policyvault.entities.User;
import org.godigit.policyvault.repository.RoleRepository;
import org.godigit.policyvault.repository.UserRepository;
import org.godigit.policyvault.security.JwtUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.constraints.NotBlank;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authManager;
    private final JwtUtils jwtUtils;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public record RegisterRequest(@NotBlank String username, @NotBlank String password, @NotBlank String role) {}
    public record LoginRequest(@NotBlank String username, @NotBlank String password) {}
    public record JwtResponse(String token) {}

    @PostMapping("/register")
    public String register(@RequestBody RegisterRequest request) {
        if (userRepository.existsByUsername(request.username())) {
            return "Username already exists!";
        }
        Role role = roleRepository.findByName("ROLE_" + request.role().toUpperCase())
                .orElseThrow(() -> new RuntimeException("Role not found"));
        User user = User.builder()
                .username(request.username())
                .password(passwordEncoder.encode(request.password()))
                .role(role)
                .build();
        userRepository.save(user);
        return "User registered!";
    }

    @PostMapping("/login")
    public JwtResponse login(@RequestBody LoginRequest request) {
        authManager.authenticate(new UsernamePasswordAuthenticationToken(request.username(), request.password()));
        return new JwtResponse(jwtUtils.generateToken(request.username()));
    }
}
```

## E) `SecurityConfig` (complete, no ellipses)

```java
package org.godigit.policyvault.security;

import lombok.RequiredArgsConstructor;
import org.godigit.policyvault.service.impl.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final CustomUserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/policies/**").hasAnyRole("EMPLOYEE","DEPARTMENT_HEAD","COMPLIANCE_OFFICER","ADMIN")
                .anyRequest().authenticated()
            )
            .authenticationProvider(authenticationProvider())
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(); }
}
```

> If your controllers keep `/policies` instead of `/api/policies`, update the `requestMatchers` accordingly.

---

# ✅ Low-priority suggestions

* **DTOs & mapping**: Your service mapping looks fine; consider MapStruct later if models grow.
* **Search**: `PolicyServiceImpl#searchPolicies` currently does in-memory filtering. Consider repository methods for large datasets.
* **Logging**: Add `@Slf4j` (Lombok) to controllers/services and log key events (login success/failure, policy updates).
* **Audit**: If you plan audit logs, add a servlet filter/aspect to record `user`, `action`, `resource`, `timestamp`.

---

If you want, I can generate **fully corrected versions** of the files that had `...` placeholders so you can paste them in and compile immediately.

USER SERVICE IMPL

package org.godigit.policyvault.service.impl;

import org.godigit.policyvault.entities.Role;
import org.godigit.policyvault.entities.Users;
import org.godigit.policyvault.repository.UserRepository;
import org.godigit.policyvault.service.UserService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Set;

@Service
public class UserServiceImpl implements UserService {

    private final UserRepository users;
    private final PasswordEncoder encoder;

    public UserServiceImpl(UserRepository users, PasswordEncoder encoder) {
        this.users = users;
        this.encoder = encoder;
    }

    @Override
    @Transactional
    @PreAuthorize("hasRole('ADMIN')") 
    public Users createUser(String username, String email, String rawPassword,
                            String department, Set<Role> roles) {
        Users u = new Users();
        u.setUsername(username);
        u.setEmail(email);
        u.setDepartment(department);
        u.setPasswordHash(encoder.encode(rawPassword));
        u.setRoles(roles);
        return users.save(u);
    }

    @Override
    @Transactional
    @PreAuthorize("hasAnyRole('ADMIN','COMPLIANCE_OFFICER','DEPARTMENT_HEAD','EMPLOYEE')")
    public void touchLogin(String username) {
        users.findByUsername(username).ifPresent(u -> {
            u.setLastLoginAt(Instant.now());
            users.save(u);
        });
    }
}


--------------------------------------------

CHANGE LOG SERVICE IMPL

package org.godigit.policyvault.service.impl;

import org.godigit.policyvault.dto.ChangeLogResponse;
import org.godigit.policyvault.repository.ChangeLogRepository;
import org.godigit.policyvault.service.ChangeLogService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
public class ChangeLogServiceImpl implements ChangeLogService {

    private final ChangeLogRepository changeLogRepo;

    public ChangeLogServiceImpl(ChangeLogRepository changeLogRepo) {
        this.changeLogRepo = changeLogRepo;
    }

    @Override
    @PreAuthorize("hasAnyRole('COMPLIANCE_OFFICER','ADMIN')")
    public List<ChangeLogResponse> getChangeLogs(UUID policyId) {
        return changeLogRepo.findByPolicyId(policyId).stream()
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

----------------------------

AUDIT LOG SERCIVE IMPL

package org.godigit.policyvault.service.impl;

import org.godigit.policyvault.entities.AuditLog;
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
        var log = new AuditLog();
        log.setUserId(userId);
        log.setPolicy(policyRepository.getReferenceById(policyId));
        log.setAction(action);
        auditLogRepo.save(log);
    }

    @Override
    @PreAuthorize("hasRole('ADMIN')")
    public List<AuditLog> getLogsByPolicy(UUID policyId) {
        return auditLogRepo.findByPolicyId(policyId);
    }

    @Override
    @PreAuthorize("hasRole('ADMIN')")
    public List<AuditLog> getLogsByUser(String userId) {
        return auditLogRepo.findByUserId(userId);
    }

    @Override
    public void record(String userId, UUID policyId, String action, String description, Instant ts) {
        // Currently empty, but you can implement this later.
        // No need for @PreAut

---------------------------

POLICY VERSION SERVICE IMPL

package org.godigit.policyvault.service.impl;

import org.godigit.policyvault.entities.PolicyVersion;
import org.godigit.policyvault.dto.PolicyVersionResponse;
import org.godigit.policyvault.repository.PolicyVersionRepository;
import org.godigit.policyvault.service.PolicyVersionService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
public class PolicyVersionServiceImpl implements PolicyVersionService {

    private final PolicyVersionRepository versionRepo;

    public PolicyVersionServiceImpl(PolicyVersionRepository versionRepo) {
        this.versionRepo = versionRepo;
    }

    @Override
    @PreAuthorize("hasRole('ADMIN')")
    public List<PolicyVersionResponse> getAllVersions(UUID policyId) {
        return versionRepo.findByPolicyIdOrderByVersionDesc(policyId).stream()
                .map(this::toDto)
                .toList();
    }

    @Override
    @PreAuthorize("hasRole('ADMIN')")
    public PolicyVersionResponse getVersion(UUID policyId, int version) {
        var pv = versionRepo.findByPolicyIdAndVersion(policyId, version);
        return toDto(pv);
    }

    private PolicyVersionResponse toDto(PolicyVersion pv) {
        return new PolicyVersionResponse(
                pv.getId(),
                pv.getPolicy().getId(),
                pv.getVersion(),
                pv.getContent(),
                pv.getCreatedAt()
        );
    }
}

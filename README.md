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

-----------------------------------------------

package org.godigit.policyvault.service.impl;

import java.util.Set;
import java.util.stream.Collectors;

import org.godigit.policyvault.entities.Users;
import org.godigit.policyvault.exception.UserNotFoundException;
import org.godigit.policyvault.repository.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository users;

    public CustomUserDetailsService(UserRepository users) {
        this.users = users;
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        Users u = users.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User with username '" + username + "' not found"));

        Set<SimpleGrantedAuthority> authorities = u.getRoles().stream()
                .map(Enum::name)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());

        return new User(
                u.getUsername(),
                u.getPasswordHash(),
                u.isEnabled(),
                true,
                true,
                true,
                authorities
        );
    }
}


------------------------------------------


package org.godigit.policyvault.service.impl;

import org.godigit.policyvault.entities.Policy;
import org.godigit.policyvault.entities.PolicyVersion;
import org.godigit.policyvault.entities.ChangeLog;
import org.godigit.policyvault.dto.*;
import org.godigit.policyvault.exception.PolicyNotFoundException;
import org.godigit.policyvault.repository.*;
import org.godigit.policyvault.service.PolicyService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
public class PolicyServiceImpl implements PolicyService {

    private final PolicyRepository policyRepo;
    private final PolicyVersionRepository versionRepo;
    private final ChangeLogRepository changeLogRepo;

    public PolicyServiceImpl(PolicyRepository policyRepo, PolicyVersionRepository versionRepo, ChangeLogRepository changeLogRepo) {
        this.policyRepo = policyRepo;
        this.versionRepo = versionRepo;
        this.changeLogRepo = changeLogRepo;
    }

    @Override
    @Transactional
    @PreAuthorize("hasAnyRole('COMPLIANCE_OFFICER','ADMIN')")
    public UUID createPolicy(PolicyCreateRequest request) {
        var policy = new Policy();
        policy.setTitle(request.title());
        policy.setDepartment(request.department());
        policy.setCurrentVersion(1);
        policyRepo.save(policy);

        var version = new PolicyVersion();
        version.setPolicy(policy);
        version.setVersion(1);
        version.setContent(request.content());
        versionRepo.save(version);

        return policy.getId();
    }

    @Override
    @PreAuthorize("hasAnyRole('EMPLOYEE','DEPARTMENT_HEAD','COMPLIANCE_OFFICER','ADMIN')")
    public PolicyResponse getPolicy(UUID id) {
        var policy = policyRepo.findById(id)
                .orElseThrow(() -> new PolicyNotFoundException("Policy with ID '" + id + "' not found"));

        return new PolicyResponse(
                policy.getId(),
                policy.getTitle(),
                policy.getDepartment(),
                policy.getCurrentVersion(),
                policy.getCreatedAt(),
                policy.getUpdatedAt()
        );
    }

    @Override
    @Transactional
    @PreAuthorize("hasAnyRole('COMPLIANCE_OFFICER','ADMIN')")
    public void updatePolicy(UUID id, PolicyUpdateRequest request) {
        var policy = policyRepo.findById(id)
                .orElseThrow(() -> new PolicyNotFoundException("Policy with ID '" + id + "' not found"));

        int newVersion = policy.getCurrentVersion() + 1;

        var version = new PolicyVersion();
        version.setPolicy(policy);
        version.setVersion(newVersion);
        version.setContent(request.content());
        versionRepo.save(version);

        var changeLog = new ChangeLog();
        changeLog.setPolicy(policy);
        changeLog.setOldVersion(policy.getCurrentVersion());
        changeLog.setNewVersion(newVersion);
        changeLog.setChangedBy(request.changedBy());
        changeLog.setDescription(request.description());
        changeLogRepo.save(changeLog);

        policy.setCurrentVersion(newVersion);
        policyRepo.save(policy);
    }

    @Override
    @PreAuthorize("hasRole('ADMIN')")
    public void deletePolicy(UUID id) {
        if (!policyRepo.existsById(id)) {
            throw new PolicyNotFoundException("Policy with ID '" + id + "' not found, cannot delete.");
        }
        policyRepo.deleteById(id);
    }

    @Override
    @PreAuthorize("hasAnyRole('EMPLOYEE','DEPARTMENT_HEAD','COMPLIANCE_OFFICER','ADMIN')")
    public List<PolicyResponse> searchPolicies(String department, String keyword) {
        var policies = policyRepo.findAll();

        return policies.stream()
                .filter(p -> (department == null || p.getDepartment().toLowerCase().contains(department.toLowerCase())) &&
                             (keyword == null || p.getTitle().toLowerCase().contains(keyword.toLowerCase())))
                .map(p -> new PolicyResponse(
                        p.getId(),
                        p.getTitle(),
                        p.getDepartment(),
                        p.getCurrentVersion(),
                        p.getCreatedAt(),
                        p.getUpdatedAt()
                ))
                .toList();
    }
}



---------------------------------------------------


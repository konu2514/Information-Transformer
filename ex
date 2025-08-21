package org.godigit.policyvault.service.impl;

import org.godigit.policyvault.entities.PolicyVersion;
import org.godigit.policyvault.dto.PolicyVersionResponse;
import org.godigit.policyvault.exception.ResourceNotFoundException;
import org.godigit.policyvault.repository.PolicyVersionRepository;
import org.godigit.policyvault.service.PolicyVersionService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Service
public class PolicyVersionServiceImpl implements PolicyVersionService {

    private final PolicyVersionRepository versionRepo;

    public PolicyVersionServiceImpl(PolicyVersionRepository versionRepo) {
        this.versionRepo = versionRepo;
    }

    @Override
    @Transactional(readOnly = true)
    @PreAuthorize("hasAnyRole('ADMIN','COMPLIANCE_OFFICER')")
    public List<PolicyVersionResponse> getAllVersions(UUID policyId) {
        return versionRepo.findByPolicyIdOrderByVersionDesc(policyId).stream()
                .map(this::toDto)
                .toList();
    }

    @Override
    @Transactional(readOnly = true)
    @PreAuthorize("hasAnyRole('ADMIN','COMPLIANCE_OFFICER')")
    public PolicyVersionResponse getVersion(UUID policyId, int version) {
        var pv = versionRepo.findByPolicyIdAndVersion(policyId, version);
        if (pv == null) {
            throw new ResourceNotFoundException(
                    "Policy version not found for id=" + policyId + ", version=" + version
            );
        }
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

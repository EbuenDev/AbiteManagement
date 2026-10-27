package com.enterprise.auth.repository;

import com.enterprise.auth.entity.AuthChallenge;
import com.enterprise.auth.entity.AuthChallengeStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AuthChallengeRepository extends JpaRepository<AuthChallenge, UUID> {

    Optional<AuthChallenge> findByTokenHash(String tokenHash);

    Optional<AuthChallenge> findByTokenHashAndStatus(String tokenHash, AuthChallengeStatus status);

    @Modifying
    @Query("DELETE FROM AuthChallenge a WHERE a.expiresAt < :cutoff")
    void deleteExpiredChallenges(@Param("cutoff") Instant cutoff);
}

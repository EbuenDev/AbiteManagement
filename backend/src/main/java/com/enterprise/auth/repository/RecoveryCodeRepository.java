package com.enterprise.auth.repository;

import com.enterprise.auth.entity.RecoveryCode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface RecoveryCodeRepository extends JpaRepository<RecoveryCode, UUID> {

    @Query("SELECT r FROM RecoveryCode r WHERE r.user.id = :userId AND r.usedAt IS NULL")
    List<RecoveryCode> findActiveCodesByUserId(@Param("userId") UUID userId);

    @Modifying
    @Query("DELETE FROM RecoveryCode r WHERE r.user.id = :userId")
    void deleteByUserId(@Param("userId") UUID userId);
}

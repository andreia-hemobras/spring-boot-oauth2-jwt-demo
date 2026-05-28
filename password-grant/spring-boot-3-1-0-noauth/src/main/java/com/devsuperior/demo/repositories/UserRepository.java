package com.devsuperior.demo.repositories;

import com.devsuperior.demo.entities.User;
import com.devsuperior.demo.projections.UserRolesProjection;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface UserRepository extends JpaRepository<User, Long> {

    @Query(nativeQuery = true, value =
            "SELECT u.email AS username, u.password, r.id, r.authority " +
            "FROM tb_user u " +
            "INNER JOIN tb_user_role ur " +
            "ON u.id = ur.user_id " +
            "INNER JOIN tb_role r " +
            "ON ur.role_id = r.id WHERE u.email = :email ")
    List<UserRolesProjection> searchUserAndRolesByEmail(String email);

}

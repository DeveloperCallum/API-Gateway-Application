package com.beamedcallum.common.database;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity(name = "accounts")
@Table(schema = "user_information")
public class UserEntry {
    @Id
    private String username;
    private String password;
    private String roles;
    private boolean enabled;
    private boolean expiredPassword;

    public UserEntry() {
    }

    public UserEntry(String username, String password, boolean enabled) {
        this.username = username;
        this.password = password;
        this.enabled = enabled;
    }

    public UserEntry(String username, String password, String roles, boolean enabled, boolean expiredPassword) {
        this.username = username;
        this.password = password;
        this.roles = roles;
        this.enabled = enabled;
        this.expiredPassword = expiredPassword;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getRoles() {
        return roles;
    }

    public boolean isPasswordExpired() {
        return expiredPassword;
    }

    public boolean isEnabled() {
        return enabled;
    }
}

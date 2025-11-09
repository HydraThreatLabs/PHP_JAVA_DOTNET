package com.demo.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.security.crypto.bcrypt.BCrypt;

import java.sql.*;

@RestController
@RequestMapping("/api")
public class SafeController {

    private Connection conn;

    public SafeController() throws SQLException {
        conn = DriverManager.getConnection("jdbc:sqlite:users_safe.db");
        Statement stmt = conn.createStatement();
        stmt.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)");
    }

    @PostMapping("/register")
    public String register(@RequestParam String username, @RequestParam String password) {
        if (username.length() < 3 || username.length() > 50 || password.length() < 6) {
            return "Invalid username or password length";
        }

        String hash = BCrypt.hashpw(password, BCrypt.gensalt());
        try (PreparedStatement ps = conn.prepareStatement("INSERT INTO users(username,password) VALUES(?,?)")) {
            ps.setString(1, username);
            ps.setString(2, hash);
            ps.executeUpdate();
            return "Registered safely: " + username;
        } catch (SQLException e) {
            return "Error: " + e.getMessage();
        }
    }

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password) {
        try (PreparedStatement ps = conn.prepareStatement("SELECT password FROM users WHERE username=?")) {
            ps.setString(1, username);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                String hash = rs.getString("password");
                if (BCrypt.checkpw(password, hash)) {
                    return "Login OK (safe)";
                }
            }
            return "Invalid credentials";
        } catch (SQLException e) {
            return "Error: " + e.getMessage();
        }
    }
}

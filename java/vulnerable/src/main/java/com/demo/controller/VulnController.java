package com.demo.controller;

import org.springframework.web.bind.annotation.*;
import java.sql.*;

@RestController
@RequestMapping("/api")
public class VulnController {

    private final Connection conn;

    public VulnController() throws SQLException {
        conn = DriverManager.getConnection("jdbc:sqlite:users_vuln.db");
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)");
        }
    }

    @PostMapping("/register")
    public String register(@RequestParam String username, @RequestParam String password) throws SQLException {
        // INTENTIONAL: vulnerable to SQLi and stores plain text password
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("INSERT INTO users(username,password) VALUES('" + username + "','" + password + "')");
            return "Registered (vulnerable): " + username;
        } catch (SQLException e) {
            return "DB error";
        }
    }

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            ResultSet rs = stmt.executeQuery("SELECT id FROM users WHERE username='" + username + "' AND password='" + password + "'");
            return rs.next() ? "Login OK (vulnerable)" : "Invalid credentials";
        } catch (SQLException e) {
            return "DB error";
        }
    }
}

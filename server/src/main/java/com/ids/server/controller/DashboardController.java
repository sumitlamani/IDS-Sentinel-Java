package com.ids.server.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class DashboardController {

    @GetMapping("/")
    public String index(Model model, jakarta.servlet.http.HttpSession session) {
        if (session.getAttribute("user") == null) {
            return "redirect:/login";
        }
        model.addAttribute("username", session.getAttribute("user"));
        model.addAttribute("role", session.getAttribute("role"));
        return "index";
    }

    @GetMapping("/login")
    public String login(jakarta.servlet.http.HttpSession session) {
        if (session.getAttribute("user") != null) {
            return "redirect:/";
        }
        return "login";
    }

    @org.springframework.web.bind.annotation.PostMapping("/login")
    @org.springframework.web.bind.annotation.ResponseBody
    public org.springframework.http.ResponseEntity<java.util.Map<String, String>> loginPost(
            @org.springframework.web.bind.annotation.RequestBody java.util.Map<String, String> payload, 
            jakarta.servlet.http.HttpSession session) {
        
        String username = payload.get("username");
        String password = payload.get("password");
        java.util.Map<String, String> response = new java.util.HashMap<>();
        
        if ("admin".equals(username) && "admin123".equals(password)) {
            session.setAttribute("user", username);
            session.setAttribute("role", "admin");
            response.put("status", "ok");
            response.put("role", "admin");
            return org.springframework.http.ResponseEntity.ok(response);
        }
        
        response.put("status", "error");
        response.put("message", "Invalid credentials");
        return org.springframework.http.ResponseEntity.status(401).body(response);
    }
    
    @GetMapping("/logout")
    public String logout(jakarta.servlet.http.HttpSession session) {
        session.invalidate();
        return "redirect:/login";
    }
}

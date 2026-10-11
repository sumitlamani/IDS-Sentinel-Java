package com.ids.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class ServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(ServerApplication.class, args);
        System.out.println("\n\033[1;96m    IDS//SENTINEL v3 (Java Edition)\033[0m");
        System.out.println("\033[92m    http://localhost:8080\033[0m");
        System.out.println("\033[93m    Login: admin / admin123\033[0m\n");
    }
}

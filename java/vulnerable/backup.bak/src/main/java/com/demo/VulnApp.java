package com.demo;

import java.util.Scanner;

public class VulnApp {
    public static void main(String[] args) {
        System.out.println("VULNERABLE app: Wczytaj linię i ją wypisz (EDU demo)");
        Scanner sc = new Scanner(System.in);
        System.out.print("Wpisz coś: ");
        if (sc.hasNextLine()) {
            String line = sc.nextLine();
            System.out.println("Echo: " + line);
        } else {
            System.out.println("Brak wejścia.");
        }
        sc.close();
    }
}

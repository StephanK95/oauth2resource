package com.klamann.oauth2resource;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class Student {

    private Long id;
    private String firstname;
    private String lastname;
    private String email;
}

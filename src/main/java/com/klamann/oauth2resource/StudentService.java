package com.klamann.oauth2resource;

import lombok.extern.log4j.Log4j;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@Log4j2
public class StudentService {

    List<Student> studentList = List.of(
            new Student(1L, "Stephan", "Klamann", "sklamann@googlemail.com"),
            new Student(2L, "Christoph", "Klamann", "christoph@gmail.com")

    );

    public List<Student> getAllStudents () {
        return studentList;
    }


}

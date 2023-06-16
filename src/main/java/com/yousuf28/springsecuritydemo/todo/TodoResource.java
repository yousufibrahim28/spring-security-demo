package com.yousuf28.springsecuritydemo.todo;

import jakarta.annotation.security.RolesAllowed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
//@CrossOrigin(origins = "http://localhost:3000")
public class TodoResource {

    private Logger logger = LoggerFactory.getLogger(getClass());

    private static final List<Todo> TODO_LIST = List.of(new Todo("yousuf28","Learn AWS"),
            new Todo("yousuf28", "Get AWS Certified"));
    @GetMapping("/todos")
    public List<Todo> helloWorld() {
        return TODO_LIST;
    }


    @GetMapping("/users/{username}/todos")
    @PreAuthorize("hasRole('USER') and #username == authentication.name")
    @PostAuthorize("returnObject.username == 'yousuf28'")
    @RolesAllowed({"ADMIN", "USER"})
    @Secured({"ROLE_ADMIN", "ROLE_USER"})
    public Todo retrieveTodosForSpecificUser(@PathVariable String username) {
        return TODO_LIST.get(0);
    }

    @PostMapping("/users/{username}/todos")
    public void createTodosForSpecificUser(@PathVariable String username, @RequestBody Todo todo) {

        logger.info("Create {} for {}", todo, username);
        //return TODO_LIST.get(0);
    }
}
record Todo (String username, String description){}

package io.github.dflippojr.payerworkbench.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Entry point: serves the workbench REST API and the static UI under {@code static/}. */
@SpringBootApplication
public class WorkbenchApplication {

    public static void main(String[] args) {
        SpringApplication.run(WorkbenchApplication.class, args);
    }
}

package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.payerworkbench.samples.SampleCatalog;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/** Entry point: serves the workbench REST API and the static UI under {@code static/}. */
@SpringBootApplication
@EnableConfigurationProperties(WorkbenchProperties.class)
public class WorkbenchApplication {

    public static void main(String[] args) {
        SpringApplication.run(WorkbenchApplication.class, args);
    }

    @Bean
    SampleCatalog sampleCatalog() {
        return new SampleCatalog();
    }
}

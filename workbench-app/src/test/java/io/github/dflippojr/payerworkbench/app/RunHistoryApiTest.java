package io.github.dflippojr.payerworkbench.app;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.payerworkbench.core.OnboardingRun;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** A fresh, bounded store exercises collection HTTP behavior without executing any payer calls. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "workbench.max-runs=2")
class RunHistoryApiTest {
    @Autowired
    RunStore store;
    @Value("${local.server.port}")
    int port;
    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void collectionStartsEmptyAndReturnsOnlyRetainedRunsNewestFirst() throws Exception {
        assertEquals("[]", get("/api/runs").body());
        for (String id : List.of("oldest", "middle", "newest")) {
            store.save(new OnboardingRun(id, "synthetic-payer", Environment.SANDBOX, List.of(), List.of()));
        }
        var response = get("/api/runs");
        assertEquals(200, response.statusCode());
        var history = mapper.readTree(response.body());
        assertEquals(List.of("newest", "middle"), history.findValuesAsText("runId"));
        assertEquals(404, get("/api/runs/oldest").statusCode());
        assertEquals(200, get("/api/runs/middle").statusCode());
    }

    private HttpResponse<String> get(String path) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }
}

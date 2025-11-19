package redhat.jenkins.plugins.rhda.utils;

import java.util.Set;
import java.util.concurrent.ExecutionException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import hudson.EnvVars;
import io.github.guacsec.trustifyda.api.v5.AnalysisReport;
import io.github.guacsec.trustifyda.api.v5.Severity;

public class UtilsTest extends BaseTest {

    @Test
    public void testUtilsFunctions() {
        System.setProperty("os.name", "Linux");
        assertTrue(Utils.isLinux());
        assertFalse(Utils.isWindows());
        assertFalse(Utils.isMac());

        System.setProperty("sun.arch.data.model", "64");
        assertTrue(Utils.is64());
        assertFalse(Utils.is32());

        String validJson = "{ 'a_b': 10}";
        assertTrue(Utils.isJSONValid(validJson));

        String invalidJson = "abcdefgh";
        assertFalse(Utils.isJSONValid(invalidJson));
    }

    @Test
    public void testGetAllHighestSeveritiesFromResponse()
            throws JsonProcessingException, ExecutionException, InterruptedException {
        String exhortResponse = this.getStringFromFile("exhort_responses", "exhort_response.json");
        ObjectMapper om = new ObjectMapper();
        AnalysisReport exhortResponseObject = om.readValue(exhortResponse, AnalysisReport.class);
        Set<Severity> allHighestSeveritiesFromResponse =
                Utils.getAllHighestSeveritiesFromResponse(exhortResponseObject);
        allHighestSeveritiesFromResponse.forEach(severity -> System.out.println(severity.toString()));
        assertEquals(allHighestSeveritiesFromResponse, Set.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM));
    }

    @Test
    public void testIsHighestVulnerabilityAllowedExceeded() {
        assertTrue(Utils.isHighestVulnerabilityAllowedExceeded(
                Set.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM), Severity.HIGH));
        assertTrue(Utils.isHighestVulnerabilityAllowedExceeded(
                Set.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM), Severity.MEDIUM));
        assertFalse(Utils.isHighestVulnerabilityAllowedExceeded(
                Set.of(Severity.HIGH, Severity.MEDIUM, Severity.LOW), Severity.HIGH));
        assertFalse(Utils.isHighestVulnerabilityAllowedExceeded(Set.of(Severity.LOW), Severity.MEDIUM));
        assertFalse(
                Utils.isHighestVulnerabilityAllowedExceeded(Set.of(Severity.LOW, Severity.MEDIUM), Severity.MEDIUM));
        assertFalse(Utils.isHighestVulnerabilityAllowedExceeded(Set.of(), Severity.LOW));
        assertFalse(Utils.isHighestVulnerabilityAllowedExceeded(Set.of(Severity.LOW), Severity.LOW));
        assertTrue(Utils.isHighestVulnerabilityAllowedExceeded(Set.of(Severity.MEDIUM), Severity.LOW));
        assertFalse(Utils.isHighestVulnerabilityAllowedExceeded(
                Set.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM), Severity.CRITICAL));
        assertTrue(Utils.isHighestVulnerabilityAllowedExceeded(
                Set.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM), Severity.HIGH));
    }
    // Test together both methods
    @Test
    public void testGetAllHighestSeveritiesFromResponseAndTestIsHighestVulnerabilityAllowedExceeded()
            throws JsonProcessingException, ExecutionException, InterruptedException {
        String exhortResponse = this.getStringFromFile("exhort_responses", "exhort_response.json");
        ObjectMapper om = new ObjectMapper();
        AnalysisReport exhortResponseObject = om.readValue(exhortResponse, AnalysisReport.class);
        Set<Severity> allHighestSeveritiesFromResponse =
                Utils.getAllHighestSeveritiesFromResponse(exhortResponseObject);
        assertTrue(Utils.isHighestVulnerabilityAllowedExceeded(allHighestSeveritiesFromResponse, Severity.HIGH));
        assertTrue(Utils.isHighestVulnerabilityAllowedExceeded(allHighestSeveritiesFromResponse, Severity.MEDIUM));
        assertTrue(Utils.isHighestVulnerabilityAllowedExceeded(allHighestSeveritiesFromResponse, Severity.LOW));
        assertFalse(Utils.isHighestVulnerabilityAllowedExceeded(allHighestSeveritiesFromResponse, Severity.CRITICAL));
    }

    @Test
    public void testSetTrustifyDaSystemProperties() {
        EnvVars envVars = new EnvVars();
        envVars.put("TRUSTIFY_DA_BACKEND_URL", "https://rhda.rhcloud.com");
        Utils.setTrustifyDaSystemProperties(envVars);
        assertEquals(System.getProperty("TRUSTIFY_DA_BACKEND_URL"), "https://rhda.rhcloud.com");

        for (String property : Utils.TRUSTIFY_DA_SYSTEM_PROPERTIES) {
            assertEquals(System.getProperty(property), null);
        }

        envVars.put("TRUSTIFY_DA_MVN_PATH", "/path/to/custom/mvn");
        Utils.setTrustifyDaSystemProperties(envVars);
        assertEquals(System.getProperty("TRUSTIFY_DA_MVN_PATH"), "/path/to/custom/mvn");
        for (String property : Utils.TRUSTIFY_DA_SYSTEM_PROPERTIES) {
            if (property.equals("TRUSTIFY_DA_MVN_PATH")) {
                continue;
            }
            assertEquals(System.getProperty(property), null);
        }
        clearSystemProperties();
    }

    @Test
    public void testSetTrustifyDaSystemPropertiesWithNoEnvVars() {
        Utils.setTrustifyDaSystemProperties(null);
        assertEquals(System.getProperty("TRUSTIFY_DA_BACKEND_URL"), "https://rhda.rhcloud.com");
        for (String property : Utils.TRUSTIFY_DA_SYSTEM_PROPERTIES) {
            assertEquals(System.getProperty(property), null);
        }
        clearSystemProperties();
    }

    private void clearSystemProperties() {
        for (String property : Utils.TRUSTIFY_DA_SYSTEM_PROPERTIES) {
            System.clearProperty(property);
        }
        System.clearProperty("TRUSTIFY_DA_BACKEND_URL");
    }
}

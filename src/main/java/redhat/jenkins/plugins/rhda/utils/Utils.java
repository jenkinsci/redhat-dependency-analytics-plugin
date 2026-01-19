/* Copyright © 2021 Red Hat Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# Author: Yusuf Zainee <yzainee@redhat.com>
*/

package redhat.jenkins.plugins.rhda.utils;

import hudson.EnvVars;
import io.github.guacsec.trustifyda.api.v5.AnalysisReport;
import io.github.guacsec.trustifyda.api.v5.Issue;
import io.github.guacsec.trustifyda.api.v5.Severity;
import java.io.IOException;
import java.io.PrintStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class Utils {

    public static final String TRUST_DA_TOKEN_PROPERTY = "TRUST_DA_TOKEN";
    public static final String TRUST_DA_SOURCE_PROPERTY = "TRUST_DA_SOURCE";
    public static final String TRUST_DA_SOURCE_VALUE = "jenkins-plugin";
    public static final String CONSENT_TELEMETRY_PROPERTY = "CONSENT_TELEMETRY";

    static final String[] TRUSTIFY_DA_SYSTEM_PROPERTIES = {
        "TRUSTIFY_DA_DEBUG",
        "TRUSTIFY_DA_PROXY_URL",
        "TRUSTIFY_DA_MVN_PATH",
        "TRUSTIFY_DA_GRADLE_PATH",
        "TRUSTIFY_DA_NPM_PATH",
        "TRUSTIFY_DA_YARN_PATH",
        "TRUSTIFY_DA_PNPM_PATH",
        "TRUSTIFY_DA_GO_PATH",
        "TRUSTIFY_DA_MVN_USER_SETTINGS",
        "TRUSTIFY_DA_MVN_LOCAL_REPO",
        "TRUSTIFY_DA_PYTHON3_PATH",
        "TRUSTIFY_DA_PIP3_PATH",
        "TRUSTIFY_DA_GO_MVS_LOGIC_ENABLED",
        "MATCH_MANIFEST_VERSIONS",
        "TRUSTIFY_DA_PIP_PATH",
        "TRUSTIFY_DA_PIP_FREEZE",
        "TRUSTIFY_DA_PIP_SHOW",
        "TRUSTIFY_DA_PIP_USE_DEP_TREE",
        "TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS",
        "TRUSTIFY_DA_PYTHON_VIRTUAL_ENV",
        "TRUSTIFY_DA_PYTHON_INSTALL_BEST_EFFORTS",
        "TRUSTIFY_DA_IGNORE_METHOD"
    };

    private static final String TRUSTIFY_DA_BACKEND_URL_PROPERTY = "TRUSTIFY_DA_BACKEND_URL";
    private static final String RHDA_BACKEND_URL = "https://rhda.rhcloud.com";

    public static void setTrustifyDaSystemProperties(EnvVars envVars) {

        if (envVars != null && envVars.get(TRUSTIFY_DA_BACKEND_URL_PROPERTY) != null) {
            System.setProperty(TRUSTIFY_DA_BACKEND_URL_PROPERTY, envVars.get(TRUSTIFY_DA_BACKEND_URL_PROPERTY));
        } else {
            System.setProperty(TRUSTIFY_DA_BACKEND_URL_PROPERTY, RHDA_BACKEND_URL);
        }
        if (envVars == null) {
            return;
        }
        for (String property : TRUSTIFY_DA_SYSTEM_PROPERTIES) {
            if (envVars.get(property) != null) {
                System.setProperty(property, envVars.get(property));
            } else {
                System.clearProperty(property);
            }
        }
    }

    public static String doExecute(String cmd, PrintStream logger, Map<String, String> envs) {
        return new CommandExecutor().execute(cmd, logger, envs);
    }

    public static boolean isJSONValid(String test) {
        try {
            new JSONObject(test);
        } catch (JSONException ex) {
            try {
                new JSONArray(test);
            } catch (JSONException ex1) {
                return false;
            }
        }
        return true;
    }

    public static boolean urlExists(String urlStr) {
        int responseCode = 404;
        try {
            URL url = new URL(urlStr);
            HttpURLConnection huc = (HttpURLConnection) url.openConnection();
            responseCode = huc.getResponseCode();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return HttpURLConnection.HTTP_OK == responseCode;
    }

    public static String getOperatingSystem() {
        String os = System.getProperty("os.name");
        return os;
    }

    public static boolean isWindows() {
        String os = getOperatingSystem();
        return os.toLowerCase().contains("win");
    }

    public static boolean isLinux() {
        String os = getOperatingSystem();
        return os.toLowerCase().contains("lin");
    }

    public static boolean isMac() {
        String os = getOperatingSystem();
        return os.toLowerCase().contains("mac");
    }

    public static boolean is32() {
        return System.getProperty("sun.arch.data.model").equals("32");
    }

    public static boolean is64() {
        return System.getProperty("sun.arch.data.model").equals("64");
    }

    public static boolean isHighestVulnerabilityAllowedExceeded(
            Set<Severity> severities, Severity highestAllowedSeverity) {
        boolean result = false;
        for (Severity severity : severities) {
            if (severity.ordinal() < highestAllowedSeverity.ordinal()) {
                result = true;
                break;
            }
        }
        return result;
    }

    public static Set<Severity> getAllHighestSeveritiesFromResponse(AnalysisReport analysisReport)
            throws InterruptedException, ExecutionException {
        return analysisReport.getProviders().entrySet().stream()
                .map(entry -> entry.getValue().getSources())
                .map(source -> source.entrySet())
                .flatMap(Collection::stream)
                .map(source -> source.getValue())
                .filter(Objects::nonNull)
                .map(t -> t.getDependencies())
                .flatMap(Collection::stream)
                .filter(Objects::nonNull)
                .map(dependency -> dependency.getHighestVulnerability())
                .filter(Objects::nonNull)
                .map(Issue::getSeverity)
                .collect(Collectors.toSet());
    }
}

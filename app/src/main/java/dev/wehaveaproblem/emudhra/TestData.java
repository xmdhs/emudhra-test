package dev.wehaveaproblem.emudhra;

import android.content.res.AssetManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Loads the embedded copies of the eMudhra test chains published with the
 * incident page (see tools/fetch_data.py).
 */
final class TestData {

    static final class Chain {
        final String host;
        final String kind;
        final String generation;
        final String rootName;
        final boolean crossSigned;
        final List<X509Certificate> certificates;

        Chain(String host, String kind, String generation, String rootName,
              boolean crossSigned, List<X509Certificate> certificates) {
            this.host = host;
            this.kind = kind;
            this.generation = generation;
            this.rootName = rootName;
            this.crossSigned = crossSigned;
            this.certificates = certificates;
        }

        String label() {
            return kind + " · " + generation;
        }
    }

    static final class Root {
        final String name;
        final String role;
        final String sha256;
        final X509Certificate certificate;

        Root(String name, String role, String sha256, X509Certificate certificate) {
            this.name = name;
            this.role = role;
            this.sha256 = sha256;
            this.certificate = certificate;
        }
    }

    final List<Chain> chains = new ArrayList<>();
    final List<Root> roots = new ArrayList<>();

    private TestData() {
    }

    static TestData load(AssetManager assets) throws Exception {
        String json = readAsset(assets, "tests.json");
        JSONObject document = new JSONObject(json);
        TestData data = new TestData();

        JSONArray rootsJson = document.getJSONArray("roots");
        for (int i = 0; i < rootsJson.length(); i++) {
            JSONObject entry = rootsJson.getJSONObject(i);
            X509Certificate cert = parseCertificates(entry.getString("pem")).get(0);
            data.roots.add(new Root(
                    entry.getString("name"),
                    entry.getString("role"),
                    entry.getString("sha256"),
                    cert));
        }

        JSONArray chainsJson = document.getJSONArray("chains");
        for (int i = 0; i < chainsJson.length(); i++) {
            JSONObject entry = chainsJson.getJSONObject(i);
            List<X509Certificate> chain = parseCertificates(entry.getString("pem"));
            completeWithRoot(chain, data.roots);
            data.chains.add(new Chain(
                    entry.getString("host"),
                    entry.getString("kind"),
                    entry.getString("generation"),
                    entry.getString("root"),
                    entry.getBoolean("cross_signed"),
                    chain));
        }
        return data;
    }

    /**
     * The published chain files stop at the last certificate the server sends,
     * which is the intermediate (cross-signed case) or the root (eMudhra case).
     * Append the matching published root so the path is complete offline.
     */
    private static void completeWithRoot(List<X509Certificate> chain, List<Root> roots) {
        if (chain.isEmpty()) {
            return;
        }
        X509Certificate last = chain.get(chain.size() - 1);
        if (last.getSubjectX500Principal().equals(last.getIssuerX500Principal())) {
            return;
        }
        for (Root root : roots) {
            X509Certificate candidate = root.certificate;
            if (!candidate.getSubjectX500Principal().equals(last.getIssuerX500Principal())) {
                continue;
            }
            try {
                last.verify(candidate.getPublicKey());
            } catch (Exception ignored) {
                continue;
            }
            chain.add(candidate);
            return;
        }
    }

    private static List<X509Certificate> parseCertificates(String pem) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        InputStream input = new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII));
        Collection<? extends Certificate> parsed;
        try {
            parsed = factory.generateCertificates(input);
        } finally {
            input.close();
        }
        List<X509Certificate> result = new ArrayList<>(parsed.size());
        for (Certificate certificate : parsed) {
            result.add((X509Certificate) certificate);
        }
        return result;
    }

    private static String readAsset(AssetManager assets, String name) throws IOException {
        InputStream input = assets.open(name);
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = input.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            return out.toString("UTF-8");
        } finally {
            input.close();
        }
    }
}

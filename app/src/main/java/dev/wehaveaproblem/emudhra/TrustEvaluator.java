package dev.wehaveaproblem.emudhra;

import java.security.KeyStore;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Evaluates the embedded chains against the device's own platform trust store.
 *
 * <p>The authoritative answer comes from the same {@link X509TrustManager}
 * Android uses for every TLS connection, so the result describes what an app on
 * this device would accept. The manual signature/validity walk beforehand only
 * guards against corrupt embedded data and produces a readable explanation.
 *
 * <p>This is the trust-store question, not a full TLS probe: a real connection
 * additionally enforces host names and, for some callers, certificate
 * transparency. The incident page's own offline instructions compare against a
 * trust store in the same way, and it is the part that an OS update fixes.
 */
final class TrustEvaluator {

    enum Verdict {
        /** The platform accepted the chain. */
        TRUSTED,
        /** The platform rejected the chain. */
        UNTRUSTED
    }

    static final class Result {
        final Verdict verdict;
        final String reason;

        Result(Verdict verdict, String reason) {
            this.verdict = verdict;
            this.reason = reason;
        }
    }

    private final X509TrustManager trustManager;
    private final List<X509Certificate> acceptedIssuers;

    TrustEvaluator() throws Exception {
        TrustManagerFactory factory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init((KeyStore) null);
        X509TrustManager found = null;
        for (TrustManager manager : factory.getTrustManagers()) {
            if (manager instanceof X509TrustManager) {
                found = (X509TrustManager) manager;
                break;
            }
        }
        if (found == null) {
            throw new IllegalStateException("No X509TrustManager available");
        }
        trustManager = found;
        acceptedIssuers = Arrays.asList(found.getAcceptedIssuers());
    }

    int acceptedIssuerCount() {
        return acceptedIssuers.size();
    }

    /**
     * True when the given root is a trust anchor on this device.
     *
     * <p>Anchors are matched the way PKIX does it: identical subject and
     * identical public key. The certificates need not be byte-identical,
     * because the same root can be published in several encodings.
     */
    boolean isTrustAnchor(X509Certificate certificate) {
        for (X509Certificate issuer : acceptedIssuers) {
            if (issuer.getSubjectX500Principal()
                    .equals(certificate.getSubjectX500Principal())
                    && Arrays.equals(issuer.getPublicKey().getEncoded(),
                    certificate.getPublicKey().getEncoded())) {
                return true;
            }
        }
        return false;
    }

    /** The anchors in the embedded chain that this device currently installs. */
    List<X509Certificate> installedAnchors(TestData.Chain chain) {
        List<X509Certificate> anchors = new ArrayList<>();
        for (X509Certificate certificate : chain.certificates) {
            if (isTrustAnchor(certificate)) {
                anchors.add(certificate);
            }
        }
        return anchors;
    }

    Result evaluate(TestData.Chain chain) {
        List<X509Certificate> certificates = chain.certificates;

        String damaged = checkChainIntegrity(certificates);
        if (damaged != null) {
            return new Result(Verdict.UNTRUSTED, damaged);
        }

        X509Certificate[] array = certificates.toArray(new X509Certificate[0]);
        try {
            // "ECDHE_ECDSA" matches the EC leaf keys used by all twelve hosts.
            trustManager.checkServerTrusted(array, "ECDHE_ECDSA");
            return new Result(Verdict.TRUSTED,
                    "本机信任库仍包含该链的根证书，系统校验证书路径通过："
                            + "在本设备上，持有对应中间 CA 私钥的人可以冒充该主机。");
        } catch (CertificateException e) {
            List<X509Certificate> anchors = installedAnchors(chain);
            if (anchors.isEmpty()) {
                return new Result(Verdict.UNTRUSTED,
                        "链上没有任何证书能对应到设备信任库中的信任锚，"
                                + "说明相关根证书已被移除或从未包含在系统中。");
            }
            return new Result(Verdict.UNTRUSTED,
                    "根证书仍在信任库中，但系统拒绝该链：" + messagesOf(e));
        } catch (RuntimeException e) {
            return new Result(Verdict.UNTRUSTED, "系统校验失败：" + e);
        }
    }

    /**
     * Verifies every signature and validity period below the top certificate.
     * Returns a description of the problem, or {@code null} when intact.
     */
    private static String checkChainIntegrity(List<X509Certificate> certificates) {
        for (int i = 0; i < certificates.size() - 1; i++) {
            X509Certificate child = certificates.get(i);
            if (!signedBy(child, certificates.get(i + 1))) {
                return "链上第 " + (i + 1) + " 个证书（自上而下）的签名无效，"
                        + "内置证书数据可能已损坏。";
            }
            try {
                child.checkValidity(new Date());
            } catch (Exception e) {
                return "证书不在有效期内：" + child.getSubjectX500Principal().getName();
            }
        }
        return null;
    }

    private static String messagesOf(Throwable throwable) {
        List<String> messages = new ArrayList<>();
        Throwable cause = throwable;
        while (cause != null) {
            if (cause instanceof CertPathValidatorException || cause == throwable) {
                String message = cause.getMessage();
                if (message != null && !message.isEmpty() && !messages.contains(message)) {
                    messages.add(message);
                }
            }
            cause = cause.getCause();
        }
        if (messages.isEmpty()) {
            String message = throwable.getMessage();
            messages.add(message == null ? throwable.getClass().getSimpleName() : message);
        }
        StringBuilder text = new StringBuilder();
        for (String message : messages) {
            if (text.length() > 0) {
                text.append(" / ");
            }
            text.append(localize(message));
        }
        return text.toString();
    }

    private static String localize(String message) {
        String lower = message.toLowerCase();
        if (lower.contains("trust anchor")) {
            return "找不到信任锚，该根证书不在设备信任库中";
        }
        if (lower.contains("transparency")) {
            return "证书透明度（CT）校验未通过";
        }
        if (lower.contains("revoked")) {
            return "证书已被吊销";
        }
        if (lower.contains("expired")) {
            return "证书已过期";
        }
        return message;
    }

    private static boolean signedBy(X509Certificate child, X509Certificate parent) {
        if (!child.getIssuerX500Principal().equals(parent.getSubjectX500Principal())) {
            return false;
        }
        try {
            child.verify(parent.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}

package dev.wehaveaproblem.emudhra;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLHandshakeException;

/**
 * The web page's check, reproduced as literally as possible: request one of the
 * twelve test hosts and see whether this app's TLS stack accepts the chain the
 * host serves.
 *
 * <p>Doing it with {@link HttpsURLConnection} rather than a bare socket means
 * the platform's own host name verification applies on every supported API
 * level, the same way it does for any other HTTPS traffic in the app. Unlike a
 * browser {@code fetch()} we can classify the outcome: a certificate rejection
 * is told apart from a plain network problem.
 */
final class NetworkProbe {

    private static final int TIMEOUT_MS = 8000;

    enum Verdict {
        /** The request got a response: the chain is still trusted. */
        CONNECTED,
        /** The request failed while validating the certificate. */
        CERT_REJECTED,
        /** The host could not be reached, so nothing can be concluded. */
        UNREACHABLE
    }

    static final class Result {
        final Verdict verdict;
        final String detail;

        Result(Verdict verdict, String detail) {
            this.verdict = verdict;
            this.detail = detail;
        }
    }

    private NetworkProbe() {
    }

    static Result probe(String host) {
        HttpsURLConnection connection = null;
        try {
            connection = (HttpsURLConnection) new URL("https://" + host + "/").openConnection();
            connection.setConnectTimeout(TIMEOUT_MS);
            connection.setReadTimeout(TIMEOUT_MS);
            connection.setUseCaches(false);
            connection.setRequestProperty("Cache-Control", "no-cache");
            connection.setRequestProperty("User-Agent", "emudhra-trust-checker/1.0");

            int status = connection.getResponseCode();
            // Any HTTP status means the handshake succeeded; the web page draws
            // the same conclusion from a non-network error.
            return new Result(Verdict.CONNECTED,
                    "TLS 握手成功（HTTP " + status + "），本 App 接受了该证书链。");
        } catch (UnknownHostException e) {
            return new Result(Verdict.UNREACHABLE, "无法解析主机名，可能没有网络。");
        } catch (SocketTimeoutException e) {
            return new Result(Verdict.UNREACHABLE, "连接超时，可能没有网络或服务器不可达。");
        } catch (SSLHandshakeException e) {
            if (isCertificateProblem(e)) {
                return new Result(Verdict.CERT_REJECTED, certificateMessage(e));
            }
            return new Result(Verdict.UNREACHABLE, "握手失败：" + e.getMessage());
        } catch (IOException e) {
            // Some platforms surface the handshake failure as a plain
            // IOException that merely wraps the SSLHandshakeException.
            if (isCertificateProblem(e)) {
                return new Result(Verdict.CERT_REJECTED, certificateMessage(e));
            }
            return new Result(Verdict.UNREACHABLE, "网络错误：" + e.getMessage());
        } catch (RuntimeException e) {
            return new Result(Verdict.UNREACHABLE, "连接失败：" + e);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /**
     * Android reports a certificate rejection as an SSLHandshakeException whose
     * cause chain holds a CertificateException. Anything else (protocol
     * mismatch, connection reset) is a transport problem, not a trust verdict.
     */
    private static boolean isCertificateProblem(Throwable throwable) {
        Throwable cause = throwable.getCause();
        while (cause != null) {
            if (cause instanceof CertificateException) {
                return true;
            }
            cause = cause.getCause();
        }
        return false;
    }

    private static String certificateMessage(Throwable throwable) {
        List<String> messages = new ArrayList<>();
        Throwable cause = throwable;
        while (cause != null) {
            String message = cause.getMessage();
            if (message != null && !message.isEmpty() && !messages.contains(message)) {
                messages.add(message);
            }
            cause = cause.getCause();
        }
        StringBuilder text = new StringBuilder("证书被拒绝");
        if (!messages.isEmpty()) {
            text.append("：").append(messages.get(0));
        }
        return text.toString();
    }
}

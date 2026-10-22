package dev.wehaveaproblem.emudhra;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.Bundle;
import android.util.TypedValue;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Native (non-Compose) port of the "Does your client still trust the
 * compromised intermediates?" section of
 * https://emudhra.we-have-a-problem.com/ .
 *
 * <p>Each of the twelve test hosts is checked twice:
 *
 * <ul>
 *   <li><b>实际连接</b> — exactly what the web page does: open a TLS connection
 *       to the host and see whether this app's TLS stack accepts the chain.
 *       This needs the network and therefore needs {@code INTERNET}.</li>
 *   <li><b>信任库</b> — the same chain is also verified offline against this
 *       device's trust anchors, so the answer is available even without
 *       connectivity, and it says whether the fix is in the trust store.</li>
 * </ul>
 */
public class MainActivity extends Activity {

    private static final int COLOR_BACKGROUND = Color.parseColor("#FAFAFA");
    private static final int COLOR_TEXT = Color.parseColor("#212121");
    private static final int COLOR_MUTED = Color.parseColor("#616161");
    private static final int COLOR_CARD = Color.WHITE;
    private static final int COLOR_BORDER = Color.parseColor("#E0E0E0");
    private static final int COLOR_RED = Color.parseColor("#C62828");
    private static final int COLOR_GREEN = Color.parseColor("#2E7D32");
    private static final int COLOR_AMBER = Color.parseColor("#EF6C00");

    private TestData data;
    private TrustEvaluator evaluator;
    private Exception loadError;

    private LinearLayout resultsContainer;
    private TextView summaryView;
    private TextView storeView;
    private Button runButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        try {
            data = TestData.load(getAssets());
            evaluator = new TrustEvaluator();
        } catch (Exception e) {
            loadError = e;
        }
        setContentView(buildLayout());
        runCheck();
    }

    // ---------------------------------------------------------------- layout

    private View buildLayout() {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(COLOR_BACKGROUND);

        LinearLayout column = new LinearLayout(this);
        column.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(18);
        column.setPadding(pad, dp(28), pad, dp(28));
        scroll.addView(column, new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView title = new TextView(this);
        title.setText("eMudhra 中间 CA 信任检查");
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 23);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setTextColor(COLOR_TEXT);
        column.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText("检查本机 Android 是否仍然信任 2026 年 10 月泄露私钥的 eMudhra 中间 CA。"
                + "与网页版一样，App 会向 emudhra.we-have-a-problem.com 的全部 12 个测试主机发起 TLS 连接；"
                + "同时还会离线拿本机信任库校验内置的同一批证书链。");
        subtitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        subtitle.setTextColor(COLOR_MUTED);
        subtitle.setLineSpacing(dp(3), 1f);
        addWithTopMargin(column, subtitle, dp(10));

        summaryView = new TextView(this);
        summaryView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        summaryView.setTypeface(Typeface.DEFAULT_BOLD);
        summaryView.setTextColor(COLOR_TEXT);
        summaryView.setLineSpacing(dp(4), 1f);
        column.addView(wrapInCard(summaryView), cardParams(dp(18)));

        runButton = new Button(this);
        runButton.setText("重新检查");
        runButton.setAllCaps(false);
        runButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                runCheck();
            }
        });
        column.addView(runButton, cardParams(dp(12)));

        storeView = new TextView(this);
        storeView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        storeView.setTextColor(COLOR_MUTED);
        storeView.setLineSpacing(dp(2), 1f);
        column.addView(storeView, cardParams(dp(12)));

        resultsContainer = new LinearLayout(this);
        resultsContainer.setOrientation(LinearLayout.VERTICAL);
        column.addView(resultsContainer);

        TextView footer = new TextView(this);
        footer.setText("怎么读这两个结果：\n"
                + "• 实际连接 —— 与网页版完全相同的检查：握手成功就说明本机仍然信任该链。"
                + "失败可能来自证书被拒，也可能是网络不通，App 会区分这两种情况。\n"
                + "• 信任库 —— 离线判断本机信任库里还有没有这些根证书，即系统更新真正修复的东西。\n\n"
                + "Android 默认的证书校验不检查吊销状态（CRL/OCSP），浏览器那套 OneCRL / CRLSet / CRLite "
                + "在这里不生效。若结果显示仍然信任，请尽快更新系统；没有可用更新时，"
                + "避免在该设备上登录敏感账号。\n\n"
                + "内置证书链取自 2026-10-20 发布的 chains.zip，是当时的快照；"
                + "测试用叶证书在 2027-05-03 到期。可用 tools/fetch_data.py 重新生成数据。");
        footer.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        footer.setTextColor(COLOR_MUTED);
        footer.setLineSpacing(dp(3), 1f);
        addWithTopMargin(column, footer, dp(24));

        return scroll;
    }

    private View wrapInCard(View child) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackground(roundedCard());
        int pad = dp(14);
        card.setPadding(pad, pad, pad, pad);
        card.addView(child);
        return card;
    }

    private LinearLayout.LayoutParams cardParams(int topMargin) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        params.topMargin = topMargin;
        return params;
    }

    private void addWithTopMargin(LinearLayout parent, View child, int topMargin) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        params.topMargin = topMargin;
        parent.addView(child, params);
    }

    private GradientDrawable roundedCard() {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(COLOR_CARD);
        drawable.setCornerRadius(dp(10));
        drawable.setStroke(dp(1), COLOR_BORDER);
        return drawable;
    }

    // ----------------------------------------------------------------- check

    private void runCheck() {
        if (loadError != null) {
            summaryView.setTextColor(COLOR_RED);
            summaryView.setText("无法加载内置证书数据：" + loadError);
            return;
        }
        runButton.setEnabled(false);
        runButton.setText("检查中…");
        resultsContainer.removeAllViews();
        summaryView.setTextColor(COLOR_TEXT);
        summaryView.setText("正在连接 12 个测试主机，并用本机信任库校验内置证书链…");

        new Thread(new Runnable() {
            @Override
            public void run() {
                final List<TestData.Chain> chains = data.chains;
                final List<TrustEvaluator.Result> offline = new ArrayList<>();
                for (TestData.Chain chain : chains) {
                    offline.add(evaluator.evaluate(chain));
                }

                // Probe all hosts in parallel: a serial run would spend most of
                // its time waiting on unreachable hosts.
                ExecutorService pool = Executors.newFixedThreadPool(6);
                List<Future<NetworkProbe.Result>> futures = new ArrayList<>();
                try {
                    for (final TestData.Chain chain : chains) {
                        futures.add(pool.submit(new Callable<NetworkProbe.Result>() {
                            @Override
                            public NetworkProbe.Result call() {
                                return NetworkProbe.probe(chain.host);
                            }
                        }));
                    }
                    final List<NetworkProbe.Result> online = new ArrayList<>();
                    for (Future<NetworkProbe.Result> future : futures) {
                        try {
                            online.add(future.get());
                        } catch (Exception e) {
                            online.add(new NetworkProbe.Result(
                                    NetworkProbe.Verdict.UNREACHABLE, "检查失败：" + e));
                        }
                    }
                    final String storeSummary = buildStoreSummary();
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            if (isFinishing() || isDestroyed()) {
                                return;
                            }
                            showResults(offline, online);
                            storeView.setText(storeSummary);
                            runButton.setText("重新检查");
                            runButton.setEnabled(true);
                        }
                    });
                } finally {
                    pool.shutdownNow();
                }
            }
        }, "trust-check").start();
    }

    private void showResults(List<TrustEvaluator.Result> offline,
                             List<NetworkProbe.Result> online) {
        int offlineTrusted = 0;
        int connected = 0;
        int unreachable = 0;
        for (int i = 0; i < offline.size(); i++) {
            if (offline.get(i).verdict == TrustEvaluator.Verdict.TRUSTED) {
                offlineTrusted++;
            }
            NetworkProbe.Verdict verdict = online.get(i).verdict;
            if (verdict == NetworkProbe.Verdict.CONNECTED) {
                connected++;
            } else if (verdict == NetworkProbe.Verdict.UNREACHABLE) {
                unreachable++;
            }
        }
        int total = offline.size();

        String headline;
        int color;
        if (connected > 0) {
            headline = "❌ 不安全";
            color = COLOR_RED;
        } else if (unreachable == total) {
            // No connectivity: the offline result is all we have.
            if (offlineTrusted > 0) {
                headline = "❌ 不安全";
                color = COLOR_RED;
            } else {
                headline = "✅ 已修补";
                color = COLOR_GREEN;
            }
        } else if (offlineTrusted > 0) {
            headline = "⚠️ 结果不一致";
            color = COLOR_AMBER;
        } else {
            headline = "✅ 已修补";
            color = COLOR_GREEN;
        }

        StringBuilder summary = new StringBuilder();
        summary.append(headline).append('\n');
        summary.append(String.format(Locale.ROOT,
                "实际连接：%d / %d 个主机握手成功。", connected, total));
        summary.append('\n');
        summary.append(String.format(Locale.ROOT,
                "信任库：仍然信任 %d / %d 条链。", offlineTrusted, total));
        if (connected > 0) {
            summary.append("\n任何持有对应中间 CA 私钥的人都可以在本设备上冒充这些主机，请立即更新系统。");
        } else if (unreachable > 0) {
            summary.append("\n有 ").append(unreachable)
                    .append(" 个主机无法连接，这些条目的实际连接结果无法判断，"
                            + "但信任库的离线结果不受影响。");
        } else if (offlineTrusted > 0) {
            summary.append("\n连接被拒，但离线校验仍能建立到根证书的路径——"
                    + "通常是握手阶段的额外检查（如吊销信息）挡住了，具体见各条目。");
        } else {
            summary.append("\n本设备已不再信任这些中间 CA，与网页版检查的“证书错误”结果一致。");
        }
        summaryView.setTextColor(color);
        summaryView.setText(summary.toString());

        for (int i = 0; i < data.chains.size(); i++) {
            resultsContainer.addView(buildRow(data.chains.get(i), offline.get(i), online.get(i)));
        }
    }

    private View buildRow(TestData.Chain chain, TrustEvaluator.Result offline,
                          NetworkProbe.Result online) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackground(roundedCard());
        int pad = dp(14);
        card.setPadding(pad, pad, pad, pad);

        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.HORIZONTAL);

        TextView label = new TextView(this);
        label.setText(chain.label() + " · "
                + (chain.crossSigned ? "Sectigo 交叉签名" : "eMudhra 直签"));
        label.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        label.setTypeface(Typeface.DEFAULT_BOLD);
        label.setTextColor(COLOR_TEXT);
        header.addView(label, new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        TextView badge = new TextView(this);
        badge.setText(badgeText(online));
        badge.setTextColor(badgeColor(online));
        badge.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        badge.setTypeface(Typeface.DEFAULT_BOLD);
        header.addView(badge);
        card.addView(header);

        TextView host = new TextView(this);
        host.setText(chain.host);
        host.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        host.setTextColor(COLOR_MUTED);
        host.setTypeface(Typeface.MONOSPACE);
        addWithTopMargin(card, host, dp(6));

        TextView onlineText = new TextView(this);
        onlineText.setText("实际连接：" + online.detail);
        onlineText.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        onlineText.setTextColor(COLOR_TEXT);
        onlineText.setLineSpacing(dp(2), 1f);
        addWithTopMargin(card, onlineText, dp(8));

        TextView offlineText = new TextView(this);
        offlineText.setText("信任库：" + offline.reason);
        offlineText.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        offlineText.setTextColor(COLOR_TEXT);
        offlineText.setLineSpacing(dp(2), 1f);
        addWithTopMargin(card, offlineText, dp(4));

        TextView path = new TextView(this);
        path.setText(describeChain(chain));
        path.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        path.setTextColor(COLOR_MUTED);
        path.setLineSpacing(dp(2), 1f);
        addWithTopMargin(card, path, dp(6));

        card.setLayoutParams(cardParams(dp(10)));
        return card;
    }

    /** Headline for the row follows the live connection, like the web page. */
    private String badgeText(NetworkProbe.Result online) {
        switch (online.verdict) {
            case CONNECTED:
                return "❌ 信任";
            case CERT_REJECTED:
                return "✅ 不信任";
            default:
                return "⚠️ 无法判断";
        }
    }

    private int badgeColor(NetworkProbe.Result online) {
        switch (online.verdict) {
            case CONNECTED:
                return COLOR_RED;
            case CERT_REJECTED:
                return COLOR_GREEN;
            default:
                return COLOR_AMBER;
        }
    }

    /**
     * Prints the path top-down, using the short names from the published data
     * ("EM DV TLS CA - G3B", "AAA Certificate Services", ...), which is easier
     * to follow than the full distinguished names.
     */
    private String describeChain(TestData.Chain chain) {
        StringBuilder text = new StringBuilder("链：叶证书");
        for (int i = 1; i < chain.certificates.size(); i++) {
            text.append(" → ").append(shortName(chain.certificates.get(i)));
        }
        if (chain.certificates.size() == 1) {
            text.append(" → ").append(chain.rootName);
        }
        return text.toString();
    }

    private String shortName(X509Certificate certificate) {
        String name = certificate.getSubjectX500Principal().getName();
        int cn = name.indexOf("CN=");
        if (cn >= 0) {
            int end = name.indexOf(',', cn);
            return end < 0 ? name.substring(cn + 3) : name.substring(cn + 3, end);
        }
        return name;
    }

    private String buildStoreSummary() {
        StringBuilder info = new StringBuilder();
        info.append("设备信任锚数量：").append(evaluator.acceptedIssuerCount());
        info.append('\n').append("Android ").append(Build.VERSION.RELEASE)
                .append("（API ").append(Build.VERSION.SDK_INT).append("）");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            info.append('\n').append("安全补丁级别：").append(Build.VERSION.SECURITY_PATCH);
        }
        info.append('\n').append("设备：").append(Build.MANUFACTURER).append(' ')
                .append(Build.MODEL).append(" · ").append(Build.DEVICE);

        StringBuilder roots = new StringBuilder();
        for (TestData.Root root : data.roots) {
            boolean present = evaluator.isTrustAnchor(root.certificate);
            roots.append('\n').append(present ? "• 仍在信任库  " : "• 已移除  ")
                    .append(root.name);
        }
        info.append("\n\n相关根证书：").append(roots);
        return info.toString();
    }

    private int dp(int value) {
        return (int) (value * getResources().getDisplayMetrics().density + 0.5f);
    }
}

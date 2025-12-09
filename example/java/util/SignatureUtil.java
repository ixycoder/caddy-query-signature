package example.java.util;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class SignatureUtil {

    private String secretKey;
    private String signParam;
    private String timestampParam;
    private String accessKeyParam;
    private List<String> excludeParams;

    private static final DateTimeFormatter DTF = DateTimeFormatter
            .ofPattern("yyyy-MM-dd'T'HH:mm:ss+08:00")
            .withZone(ZoneId.of("Asia/Shanghai"));

    public SignatureUtil(String secretKey) {
        this.secretKey = secretKey;
        this.signParam = "sign";
        this.timestampParam = "timestamp";
        this.accessKeyParam = "ak";
        this.excludeParams = new ArrayList<>();
    }

    public String getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public String getSignParam() {
        return signParam;
    }

    public void setSignParam(String signParam) {
        this.signParam = signParam;
    }

    public String getTimestampParam() {
        return timestampParam;
    }

    public void setTimestampParam(String timestampParam) {
        this.timestampParam = timestampParam;
    }

    public String getAccessKeyParam() {
        return accessKeyParam;
    }

    public void setAccessKeyParam(String accessKeyParam) {
        this.accessKeyParam = accessKeyParam;
    }

    public List<String> getExcludeParams() {
        return excludeParams;
    }

    public void setExcludeParams(List<String> excludeParams) {
        this.excludeParams = excludeParams;
    }

    public String generateSignature(String baseURL, String method, Map<String, List<String>> params) throws Exception {
        // 添加时间戳
        if (!timestampParam.isEmpty()) {
            String timestamp = LocalDateTime.now().format(DTF);
            params.computeIfAbsent(timestampParam, k -> new ArrayList<>()).add(timestamp);
        }

        // 检查访问密钥
        if (accessKeyParam.isEmpty()) {
            throw new IllegalArgumentException("access_key_param is required");
        }
        List<String> accessKeyValues = params.get(accessKeyParam);
        if (accessKeyValues == null || accessKeyValues.isEmpty()) {
            throw new IllegalArgumentException("access_key is empty!");
        }
        String accessKey = accessKeyValues.get(0);

        // 构建完整URL
        URI parsedURI = new URI(baseURL);

        // 构建待签名字符串
        String stringToSign = buildStringToSign(params, method, parsedURI.getPath(), accessKey);

//        System.out.println(stringToSign);

        // 计算签名
        String signature = calculateSignature(stringToSign);

        // 添加签名参数
        params.computeIfAbsent(signParam, k -> new ArrayList<>()).clear();
        params.get(signParam).add(signature);

        // 构建查询字符串
        String query = buildQueryString(params);
//        System.out.println(query);
        String finalQuery;
        if (parsedURI.getQuery() != null && !parsedURI.getQuery().isEmpty()) {
            finalQuery = parsedURI.getQuery() + "&" + query;
        } else {
            finalQuery = query;
        }

        return String.format("%s?%s",baseURL, finalQuery);
    }

    private String buildStringToSign(Map<String, List<String>> params, String method, String path, String accessKey) {
        // 按参数名排序
        List<String> keys = new ArrayList<>();
        for (String k : params.keySet()) {
            if (!k.equals(signParam) && !isExcludedParam(k)) {
                keys.add(k);
            }
        }
        Collections.sort(keys);

        // 构建参数字符串
        List<String> paramStrs = new ArrayList<>();
        for (String k : keys) {
            List<String> values = params.get(k);
            Collections.sort(values);
            for (String v : values) {
                paramStrs.add(String.format("%s=%s", k, v));
            }
        }

        return String.format("%s\n%s\n%s\n%s\n",
                method, path, String.join("&", paramStrs), accessKey);
    }

    private String calculateSignature(String data) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        hmac.init(secretKeySpec);
        byte[] hash = hmac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hash);
    }

    private boolean isExcludedParam(String param) {
        for (String exclude : excludeParams) {
            if (param.equals(exclude)) {
                return true;
            }
        }
        return false;
    }

    private String buildQueryString(Map<String, List<String>> params) throws UnsupportedEncodingException {
        StringBuilder query = new StringBuilder();
        for (Map.Entry<String, List<String>> entry : params.entrySet()) {
            String key = entry.getKey();
            List<String> values = entry.getValue();
            for (String value : values) {
                if (query.length() > 0) {
                    query.append("&");
                }
                query.append(URLEncoder.encode(key, String.valueOf(StandardCharsets.UTF_8)));
                query.append("=");
                query.append(URLEncoder.encode(value, String.valueOf(StandardCharsets.UTF_8)));
            }
        }
        return query.toString();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }


    // 测试方法
    public static void main(String[] args) throws Exception {
        SignatureUtil sg = new SignatureUtil("change-secret");
        Map<String, List<String>> params = new HashMap<>();
        params.put("userid", Collections.singletonList("change-ak"));
//        params.put("param1", Collections.singletonList("value1"));
//        params.put("param2", Arrays.asList("value2", "value3"));

        String signedLocalURL = sg.generateSignature(
                "/path/to/some.jpg",
                "GET", params);

        System.out.println("Signed URL: " + signedLocalURL);

        String signedRemoteURL = sg.generateSignature(
                "https://example.com//path/to/some.jpg",
                "GET", params);
        System.out.println("Signed URL: " + signedRemoteURL);
    }
}
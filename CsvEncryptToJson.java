import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.*;

public class CsvEncryptToJson {
    public static String generateSalt() {
        String base = "nicetryelena";
        SecureRandom random = new SecureRandom();
        int randNum = random.nextInt(1000); // 0–999
        String saltStr = base + String.format("%03d", randNum); // always 3 digits
        return Base64.getEncoder().encodeToString(saltStr.getBytes());
    }

    
    private static final SecureRandom random = new SecureRandom();
    private static final String SECRET_MESSAGE = "ImAGreeeeeeeenChicken";

    public static Map<String, String> encryptWithPassword(String plaintext, String password) throws Exception {
        String SALT = generateSalt(); 
        byte[] saltBytes = SALT.getBytes(StandardCharsets.UTF_8);

        KeySpec spec = new PBEKeySpec(password.toCharArray(), saltBytes, 65536, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        byte[] iv = new byte[16];
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        byte[] cipherText = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        Map<String, String> result = new LinkedHashMap<>();
        result.put("salt", Base64.getEncoder().encodeToString(saltBytes));
        result.put("iv", Base64.getEncoder().encodeToString(iv));
        result.put("cipher_text", Base64.getEncoder().encodeToString(cipherText));
        return result;
    }

    public static String decryptWithPassword(Map<String, String> encDict, String password) throws Exception {
        byte[] saltBytes = Base64.getDecoder().decode(encDict.get("salt"));
        byte[] iv = Base64.getDecoder().decode(encDict.get("iv"));
        byte[] cipherBytes = Base64.getDecoder().decode(encDict.get("cipher_text"));

        KeySpec spec = new PBEKeySpec(password.toCharArray(), saltBytes, 65536, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        byte[] plainBytes = cipher.doFinal(cipherBytes);
        return new String(plainBytes, StandardCharsets.UTF_8);
    }

    // --- Simple JSON serialization ---
    public static String serializeJson(Map<String, List<Map<String,String>>> data) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        boolean firstKey = true;
        for (String key : data.keySet()) {
            if (!firstKey) sb.append(",\n");
            firstKey = false;
            sb.append("  \"").append(key).append("\": [\n");
            List<Map<String,String>> list = data.get(key);
            for (int i = 0; i < list.size(); i++) {
                Map<String,String> map = list.get(i);
                sb.append("    {")
                  .append("\"salt\":\"").append(map.get("salt")).append("\",")
                  .append("\"iv\":\"").append(map.get("iv")).append("\",")
                  .append("\"cipher_text\":\"").append(map.get("cipher_text")).append("\"")
                  .append("}");
                if (i < list.size() - 1) sb.append(",");
                sb.append("\n");
            }
            sb.append("  ]");
        }
        sb.append("\n}");
        return sb.toString();
    }

    // --- Simple JSON deserialization for our format ---
    public static Map<String, List<Map<String,String>>> deserializeJson(String json) throws Exception {
        Map<String, List<Map<String,String>>> result = new LinkedHashMap<>();
        BufferedReader br = new BufferedReader(new StringReader(json));
        String line;
        String currentKey = null;
        List<Map<String,String>> currentList = null;
        while ((line = br.readLine()) != null) {
            line = line.trim();
            if (line.startsWith("\"") && line.contains("\":")) {
                currentKey = line.substring(1, line.indexOf("\":")).trim();
                currentList = new ArrayList<>();
                result.put(currentKey, currentList);
            } else if (line.startsWith("{") && line.endsWith("}") && currentList != null) {
                Map<String,String> map = new LinkedHashMap<>();
                String[] parts = line.substring(1, line.length()-1).split(",");
                for (String p : parts) {
                    String[] kv = p.split(":",2);
                    String k = kv[0].trim().replaceAll("\"","");
                    String v = kv[1].trim().replaceAll("\"","");
                    map.put(k,v);
                }
                currentList.add(map);
            }
        }
        return result;
    }

    public static void main(String[] args) throws Exception {
        File inputFile = new File("secret_crossword_answers.csv");
        BufferedReader reader = new BufferedReader(new FileReader(inputFile));

        Map<String, List<Map<String,String>>> encryptedMap = new LinkedHashMap<>();
        Map<String, List<String>> passwordMap = new LinkedHashMap<>();
        String line;

        while ((line = reader.readLine()) != null) {
            if (line.trim().isEmpty()) continue; // skip empty lines

            String[] parts = line.split(",", 3); // x,y,[answers]
            if (parts.length < 3) continue;

            String key = parts[0].trim() + "," + parts[1].trim();
            String answersRaw = parts[2].trim();

            // Remove brackets if present
            if (answersRaw.startsWith("[") && answersRaw.endsWith("]")) {
                answersRaw = answersRaw.substring(1, answersRaw.length() - 1).trim();
            }

            // Split by pipe and remove any empty strings
            String[] answersArray = answersRaw.split("\\|");
            List<String> answers = new ArrayList<>();
            for (String ans : answersArray) {
                if (!ans.trim().isEmpty()) {
                    answers.add(ans.trim());
                }
            }

            List<Map<String,String>> encList = new ArrayList<>();
            List<String> passwords = new ArrayList<>();

            for (String ans : answers) {
                String password = ans;
                passwords.add(password);
                Map<String,String> enc = encryptWithPassword(SECRET_MESSAGE, password);
                encList.add(enc);
                System.out.println("Encrypting with password: " + password);
            }

            encryptedMap.put(key, encList);
            passwordMap.put(key, passwords);
        }
        reader.close();


        // Save JSON manually
        String json = serializeJson(encryptedMap);
        try (FileWriter fw = new FileWriter("public_crossword_answers.json")) {
            fw.write(json);
        }
        System.out.println("Encrypted JSON written to public_crossword_answers.json\n");

        // --- Load JSON back from file ---
        StringBuilder sb = new StringBuilder();
        try (BufferedReader fr = new BufferedReader(new FileReader("output.json"))) {
            String l;
            while ((l = fr.readLine()) != null) sb.append(l).append("\n");
        }
        Map<String, List<Map<String,String>>> loadedMap = deserializeJson(sb.toString());

        // Decrypt using the original CSV answers (passwords)
        System.out.println("Decrypting back:");
        for (String key : loadedMap.keySet()) {
            List<Map<String,String>> encList = new ArrayList<>(loadedMap.get(key)); // make a copy
            List<String> passwords = passwordMap.get(key);

            List<String> decrypted = new ArrayList<>();

            for (String password : passwords) {
                boolean success = false;
                Iterator<Map<String,String>> it = encList.iterator();
                while (it.hasNext()) {
                    Map<String,String> enc = it.next();
                    try {
                        String plain = decryptWithPassword(enc, password);
                        decrypted.add(plain);
                        it.remove(); // remove this entry so it can't be used again
                        success = true;
                        break;
                    } catch (Exception e) {
                        // failed, try next
                    }
                }
                if (!success) {
                    decrypted.add("ERROR: " + password);
                }
            }

            System.out.print(key + " -> [");
            for (int i = 0; i < decrypted.size(); i++) {
                System.out.print(decrypted.get(i));
                if (i < decrypted.size() - 1) System.out.print(", ");
            }
            System.out.println("]");
        }

    }
}

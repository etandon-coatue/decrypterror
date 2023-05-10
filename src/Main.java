import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Base64;

public class Main {
    public static void main(String[] args) throws Exception {
        String key = "<Update to Key>";
        String message = "<Update to Message>";
        System.out.println("Hello world!");
        byte[] result = decrypt(key, message);
        System.out.println("Result: ${result}");
    }

    public static byte[] decrypt(String key, String source) throws Exception {
        int GCM_AAD_LENGTH = 16;
        int GCM_TAG_LENGTH = 16;
        int GCM_NONCE_LENGTH = 12;

        byte[] decodedKey = Base64.getDecoder().decode(key);
        byte[] decodedSource = Base64.getDecoder().decode(source);

        byte[] aad = new byte[GCM_AAD_LENGTH];
        System.arraycopy(decodedSource, 0, aad, 0, GCM_AAD_LENGTH);

        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        System.arraycopy(aad, GCM_AAD_LENGTH - GCM_NONCE_LENGTH, nonce, 0, GCM_NONCE_LENGTH);

        byte[] tag = new byte[GCM_TAG_LENGTH];
        System.arraycopy(decodedSource, decodedSource.length - GCM_TAG_LENGTH, tag, 0, GCM_TAG_LENGTH);

        byte[] encMessage = new byte[decodedSource.length - GCM_AAD_LENGTH - GCM_TAG_LENGTH];
        System.arraycopy(decodedSource, GCM_AAD_LENGTH, encMessage, 0, encMessage.length);

        SecretKeySpec secretKey = new SecretKeySpec(decodedKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParams = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParams);
        cipher.updateAAD(aad);

        byte[] decMessage = cipher.doFinal(encMessage);

        byte[] authenticated = cipher.doFinal(tag);
        if (!MessageDigest.isEqual(authenticated, tag)) {
            throw new Exception("Authentication tag mismatch!");
        }

        return decMessage;
    }
}
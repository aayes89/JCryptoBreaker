package cryptoslib;

/**
 *
 * @author Slam
 */
/* 
   LIBRERÍA EDUCATIVA PARA CIFRADO SIMÉTRICO (AES) Y ASIMÉTRICO (RSA)
   Versión 1.0 - Para propósitos didácticos
 */
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.*;
import java.math.BigInteger;

public class AES_RSA_EduLib {

    // ================== SECCIÓN AES ================== //
    public static class AES {

        /**
         * Genera clave AES de tamaño especificado (128, 192, 256 bits)
         *
         * @param keySize
         * @return
         * @throws java.lang.Exception
         */
        public static SecretKey generarClave(int keySize) throws Exception {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(keySize);
            return keyGen.generateKey();
        }

        /**
         * Cifrado AES en modo ECB con padding PKCS5
         *
         * @param texto
         * @param clave
         * @return
         * @throws java.lang.Exception
         */
        public static byte[] cifrarECB(byte[] texto, SecretKey clave) throws Exception {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, clave);
            return cipher.doFinal(texto);
        }

        /**
         * Descifrado AES en modo ECB desde Base64
         *
         * @param textoCifrado
         * @param clave
         * @return
         * @throws java.lang.Exception
         */
        public static byte[] descifrarECB(byte[] textoCifrado, SecretKey clave) throws Exception {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, clave);
            return cipher.doFinal(textoCifrado);
        }

        /**
         * Cifrado AES-CBC con IV aleatorio (devuelve arreglo: [IV, texto
         * cifrado])
         *
         * @param texto
         * @param clave
         * @return
         * @throws java.lang.Exception
         */
        public static byte[][] cifrarCBC(byte[] texto, SecretKey clave) throws Exception {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] iv = Utils.generarIV();
            cipher.init(Cipher.ENCRYPT_MODE, clave, new IvParameterSpec(iv));
            return new byte[][]{iv, cipher.doFinal(texto)};
        }

        /**
         * Descifrado AES-CBC con IV conocido
         *
         * @param iv
         * @param textoCifrado
         * @param clave
         * @return
         * @throws java.lang.Exception
         */
        public static byte[] descifrarCBC(byte[] iv, byte[] textoCifrado, SecretKey clave) throws Exception {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, clave, new IvParameterSpec(iv));
            return cipher.doFinal(textoCifrado);
        }
    }

    // ================== SECCIÓN RSA ================== //
    public static class RSA {

        /**
         * Genera par de claves RSA con tamaño específico (ej: 1024)
         *
         * @param keySize
         * @return
         * @throws java.lang.Exception
         */
        public static KeyPair generarParClaves(int keySize) throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(keySize);
            return keyGen.generateKeyPair();
        }

        /**
         * Cifrado RSA con clave pública
         *
         * @param datos
         * @param clavePublica
         * @return
         * @throws java.lang.Exception
         */
        public static byte[] cifrar(byte[] datos, PublicKey clavePublica) throws Exception {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, clavePublica);
            return cipher.doFinal(datos);
        }

        /**
         * Descifrado RSA con clave privada
         *
         * @param datosCifrados
         * @param clavePrivada
         * @return
         * @throws java.lang.Exception
         */
        public static byte[] descifrar(byte[] datosCifrados, PrivateKey clavePrivada) throws Exception {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, clavePrivada);
            return cipher.doFinal(datosCifrados);
        }
    }

    // ================== SECCIÓN ATAQUES DEMOSTRATIVOS ================== //
    public static class Ataques {

        /**
         * Demostración de ataque por fuerza bruta a AES (versión simplificada)
         *
         * @param textoCifrado
         * @param textoPlanoConocido
         * @param claveInicial Suposición inicial cercana a la real para
         * demostración
         * @param iv
         */
        public static void fuerzaBrutaAES_CBC(byte[] textoCifrado, byte[] textoPlanoConocido, byte[] claveInicial, byte[] iv) {
            // Implementación didáctica con clave de ejemplo cercana
            byte[] clavePrueba = Arrays.copyOf(claveInicial, claveInicial.length);
            //clavePrueba[clavePrueba.length - 1] = (byte) (clavePrueba[clavePrueba.length - 1] - 10);
            // Simulación de intento de adivinanza incrementando valores
            for (int i = 0; i < Long.MAX_VALUE; i++) { // Límite para demostración
                System.out.println("Intento: " + (i + 1) + " de clave: " + Utils.bytesToHex(clavePrueba));
                try {
                    SecretKeySpec clave = new SecretKeySpec(clavePrueba, "AES");
                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipher.init(Cipher.DECRYPT_MODE, clave, new IvParameterSpec(iv));
                    byte[] descifrado = cipher.doFinal(textoCifrado);

                    if (Arrays.equals(descifrado, textoPlanoConocido)) {
                        System.out.println("¡Clave encontrada!\n\t" + Utils.bytesToHex(clavePrueba) + "\n");
                        System.out.println("Texto descifrado: " + new String(descifrado));
                        return;
                    }
                } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
                    /* Ignorar errores */ }

                // Incremento secuencial
                if (!Utils.incrementKey(clavePrueba)) {
                    // Si ya se recorrieron todas las claves, salimos
                    break;
                }
            }
            System.out.println("Ataque didáctico finalizado sin éxito (esperado)");
        }

        /**
         * Demostración de ataque por fuerza bruta a AES ECB (versión
         * simplificada)
         *
         * @param textoCifrado
         * @param textoPlanoConocido
         * @param claveInicial Suposición inicial cercana a la real para
         * demostración
         */
        // Debería recibir el texto plano esperado como parámetro
        public static void fuerzaBrutaAES_ECB(byte[] textoCifrado, byte[] textoPlanoConocido, byte[] claveInicial) {
            // Implementación didáctica con clave de ejemplo cercana
            byte[] clavePrueba = Arrays.copyOf(claveInicial, claveInicial.length);
            //clavePrueba[clavePrueba.length - 1] = (byte) (clavePrueba[clavePrueba.length - 1] - 10);
            // Simulación de intento de adivinanza incrementando valores
            for (int i = 0; i < Long.MAX_VALUE; i++) { // Límite para demostración
                System.out.println("Intento: " + (i + 1) + " de clave: " + Utils.bytesToHex(clavePrueba));
                try {
                    SecretKeySpec clave = new SecretKeySpec(clavePrueba, "AES");
                    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                    cipher.init(Cipher.DECRYPT_MODE, clave);
                    byte[] descifrado = cipher.doFinal(textoCifrado);

                    if (Arrays.equals(descifrado, textoPlanoConocido)) {
                        System.out.println("¡Clave encontrada!\n\t" + Utils.bytesToHex(clavePrueba) + "\n");
                        System.out.println("Texto descifrado: " + new String(descifrado));
                        return;
                    }
                } catch (Exception e) {
                    /* Ignorar errores */ }

                // Incremento secuencial
                if (!Utils.incrementKey(clavePrueba)) {
                    // Si ya se recorrieron todas las claves, salimos
                    break;
                }
            }
            System.out.println("Ataque didáctico finalizado sin éxito (esperado)");
        }

        /**
         * Demostración de factorización de módulo RSA para obtener clave
         * privada
         *
         * @param n
         * @param e
         */
        public static void factorizarRSA(BigInteger n, BigInteger e) {
            BigInteger p = BigInteger.valueOf(61); // Valor conocido para ejemplo
            BigInteger q = n.divide(p);

            if (p.multiply(q).equals(n)) {
                BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
                BigInteger d = e.modInverse(phi);
                System.out.println("Clave privada demostrativa (d): " + d);
            } else {
                System.out.println("Factorización didáctica fallida");
            }
        }
    }

    // ================== UTILIDADES ================== //
    public static class Utils {

        public static String bytesToHex(byte[] bytes) {
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(String.format("%02X", b));
            }
            return sb.toString();
        }

        public static byte[] hexToBytes(String hex) {
            hex = hex.replaceAll(" ", "");
            byte[] bytes = new byte[hex.length() / 2];
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
            }
            return bytes;
        }

        public static boolean incrementKey(byte[] key) {
            for (int i = key.length - 1; i >= 0; i--) {
                int currentByte = key[i] & 0xFF; // Convertir a entero sin signo
                if (currentByte != 0xFF) {
                    key[i] = (byte) (currentByte + 1);
                    return true;
                }
                key[i] = 0;
            }
            return false;
        }

        public static byte[] generarIV() {
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            return iv;
        }
    }
}

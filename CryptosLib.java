package cryptoslib;

import java.security.KeyPair;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Slam
 */
public class CryptosLib {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try {
            String textoDPrueba = "Mensaje secreto conocido";
            System.out.println("Generando clave AES...");
            // Ejemplo AES
            SecretKey claveAES = AES_RSA_EduLib.AES.generarClave(128);
            System.out.println("Clave AES: " + AES_RSA_EduLib.Utils.bytesToHex(claveAES.getEncoded()));
            System.out.println("Cifrando mensaje de prueba: " + AES_RSA_EduLib.Utils.bytesToHex(textoDPrueba.getBytes()));
            byte[] cifrado = AES_RSA_EduLib.AES.cifrarECB(textoDPrueba, claveAES);
            System.out.println("\tMensaje cifrado en AES ECB Hex: " + AES_RSA_EduLib.Utils.bytesToHex(cifrado) + "\n");
            System.out.println("\tMensaje cifrado en AES ECB ASCII: " + new String(cifrado) + "\n");
            System.out.println("Descifrando mensaje de prueba en AES ECB");
            byte[] descifrado = AES_RSA_EduLib.AES.descifrarECB(cifrado, claveAES);
            System.out.println("\tMensaje descifrado en AES ECB en Hex: " + AES_RSA_EduLib.Utils.bytesToHex(descifrado) + "\n");
            System.out.println("\tMensaje descifrado en AES ECB en ASCII: " + new String(descifrado) + "\n");

            // Ejemplo RSA
            System.out.println("Rompiendo RSA");
            System.out.println("Generando KeyPair en 1024 bits");
            KeyPair clavesRSA = AES_RSA_EduLib.RSA.generarParClaves(1024);
            System.out.println("Cifrando mensaje de prueba");
            byte[] cifradoRSA = AES_RSA_EduLib.RSA.cifrar(textoDPrueba.getBytes(), clavesRSA.getPublic());
            System.out.println("\tMensaje de prueba cifrado en RSA - Hex: " + AES_RSA_EduLib.Utils.bytesToHex(cifradoRSA) + "\n");
            System.out.println("\tMensaje de prueba cifrado en RSA - ASCII: " + new String(cifradoRSA));
            System.out.println("Descifrando mensaje de prueba cifrado en RSA");
            byte[] descifradoRSA = AES_RSA_EduLib.RSA.descifrar(cifradoRSA, clavesRSA.getPrivate());
            System.out.println("Mensaje de prueba descifrado: " + AES_RSA_EduLib.Utils.bytesToHex(descifradoRSA) + "\n");
            System.out.println("Demostración de ataque a AES-CBC");
            // Demostración de ataque (uso educativo)
            System.out.println("Cifrando en AES-CBC el texto: " + textoDPrueba);
            byte[] textoPlano = textoDPrueba.getBytes();
            byte[][] cifradoCBC = AES_RSA_EduLib.AES.cifrarCBC(textoPlano, claveAES);
            // claveAES - Clave real para ejemplo didáctico
            // cifradoCBC[1] - IV
            // cifradoCBC[0] - texto cifrado
            System.out.println("Texto cifrado en RSA Hex: " + AES_RSA_EduLib.Utils.bytesToHex(cifradoCBC[0]));
            //System.out.println("Texto cifrado en RSA ASCII: " + new String(cifradoCBC[0]));
            System.out.println("IV en Hex: " + AES_RSA_EduLib.Utils.bytesToHex(cifradoCBC[1]));
            //System.out.println("IV en ASCII: " + new String(cifradoCBC[1]));
            byte[] claveAES = AES_RSA_EduLib.Utils.hexToBytes("3085DA511A98D91186669D2623D9D4C5");
            byte[] ciphedText = AES_RSA_EduLib.Utils.hexToBytes("28373943F7F2D2048B3B7010AB081458");
            byte[] ivTemp = AES_RSA_EduLib.Utils.hexToBytes("BC02861F56EBF0407076ED35B234709B9713B29065983CB05B067B1811B8F74D");
            //AES_RSA_EduLib.Ataques.fuerzaBrutaAES_CBC(cifradoCBC[1], textoPlano, claveAES.getEncoded(), cifradoCBC[0]);
            AES_RSA_EduLib.Ataques.fuerzaBrutaAES_CBC(ivTemp, textoDPrueba.getBytes(), claveAES, ciphedText);

            // Texto conocido (debe ser un bloque completo de 16 bytes para ECB)
            byte[] textoPlano = "Texto conocido1234".getBytes();

            // Cifrar con una clave conocida (ej: 0x0000...0001)
            SecretKey claveReal = /*AES_RSA_EduLib.AES.generarClave(128);//*/ new SecretKeySpec(AES_RSA_EduLib.Utils.hexToBytes("00000000000000000000000000000001"), "AES");
            byte[] cifrado = AES_RSA_EduLib.AES.cifrarECB(textoPlano, claveReal);

            // Ataque (comenzando cerca de la clave real para demostración)
            byte[] claveInicial = AES_RSA_EduLib.Utils.hexToBytes("00000000000000000000000000000000");
            AES_RSA_EduLib.Ataques.fuerzaBrutaAES_ECB(cifrado, textoPlano, claveInicial);
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
    }

}

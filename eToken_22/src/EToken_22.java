
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;

public class EToken_22 {
	
	static String plainText ;
	static Scanner input = new Scanner(System.in); 
	static PrivateKey  privateKey;
	static  PublicKey publicKey;
	
	public static void main(String[] args)
    {

		
		try {

    	
	    // Create instance of SunPKCS11 provider
     	    String pkcs11Config = "C:\\Users\\Hello\\eclipse-workspace\\EToken_22\\config.cfg";
    	    java.io.ByteArrayInputStream pkcs11ConfigStream = new java.io.ByteArrayInputStream(pkcs11Config.getBytes());
	    sun.security.pkcs11.SunPKCS11 providerPKCS11 = new sun.security.pkcs11.SunPKCS11(pkcs11Config);
	    java.security.Security.addProvider(providerPKCS11);   
	   
	    // Get provider KeyStore and login with PIN  
	    KeyStore.CallbackHandlerProtection chp = new KeyStore.CallbackHandlerProtection(new MyGuiCallbackHandler() {});
	    KeyStore.Builder builder = KeyStore.Builder.newInstance("PKCS11", null, chp);
	    KeyStore keyStore = builder.getKeyStore();

         
          
          System.out.print("\n Enter plainText : ");
          plainText = input.nextLine();
          
          
          // Enumerate items (certificates and private keys) in the KeyStore
          java.util.Enumeration<String> aliases = keyStore.aliases();	 
          String alias = null;

      
          while (aliases.hasMoreElements()) {

            alias = aliases.nextElement();
    

            Certificate cert = keyStore.getCertificate(alias);
            X509Certificate x509Certificate =  (X509Certificate)cert ;
            
            
            // x509Certificate.getKeyUsage()[2]  Check whether the certificate has : keyEncipherment 
            if( x509Certificate.getKeyUsage()[2] == true) {
            	
            Key key = keyStore.getKey(alias, null); // Here I try to access the private key of my hardware certificate
            privateKey  =  (PrivateKey )key ; 
            publicKey = x509Certificate.getPublicKey();
            
         
             // print all certificate information
             // System.out.println(cert);
           
           break;
           
            }     
          
          }
          
   
          
            // Encryption
            byte[] cipherTextArray = encrypt(plainText, publicKey );
            String encryptedText = Base64.getEncoder().encodeToString(cipherTextArray);
            System.out.println("\n Encrypted Text : "+encryptedText + "\n");
            
            
           
        
             // Decryption
             String decryptedText = decrypt(cipherTextArray,  privateKey );
             System.out.println(" Decrypted Text : "+decryptedText);  
       
		}
		
		
		catch(Exception e ) {
			e.printStackTrace();
		}
		
}
	
	
	
	
    
        public static byte[] encrypt (String plainText,PublicKey publicKey ) throws Exception
        {
            //Get Cipher Instance RSA With ECB Mode and OAEPWITHSHA-PKCS1Padding Padding
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");  
            
            //Initialize Cipher for ENCRYPT_MODE
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            
            //Perform Encryption
            byte[] cipherText = cipher.doFinal(plainText.getBytes()) ;

            return cipherText;
        
            }
        
        
        
        public static String decrypt (byte[] cipherTextArray, PrivateKey  key) throws Exception
        {
            //Get Cipher Instance RSA With ECB Mode and OAEPWITHSHA-PKCS1Padding Padding (PKCS1Padding) The reason why the extended algorithm is needed at all is compatibility with other Cipher algorithms
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); 
            
            //Initialize Cipher for DECRYPT_MODE
            cipher.init(Cipher.DECRYPT_MODE, key);
            
            //Perform Decryption
            byte[] decryptedTextArray = cipher.doFinal(cipherTextArray);
            
            return new String(decryptedTextArray);
        }
        
	}


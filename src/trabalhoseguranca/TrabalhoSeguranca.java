/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package trabalhoseguranca;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fips.FipsDRBG;
import org.bouncycastle.crypto.util.BasicEntropySourceProvider;

/**
 *
 * @author joao
 */
public class TrabalhoSeguranca {
    final static String keystoreFile = "keystore.bcfks";
    static String senhaMestra;
    private static IvParameterSpec ivSpec;
    private static Cipher cipher;

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, DecoderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, FileNotFoundException, UnrecoverableKeyException {
        // Install Provider FIPS
        Security.addProvider(new BouncyCastleFipsProvider());
        
        TrabalhoSeguranca obj = new TrabalhoSeguranca();        
        String salt;
        int it = 10000;
        Pessoa alice = new Pessoa("alice");
        Pessoa bob = new Pessoa("bob");
        Pessoa ana = new Pessoa("ana");
        Pessoa pedro = new Pessoa("pedro");

        // Adicionado para resolver problema da lentidao no Linux - Sugerido por Marcio Sagaz
        CryptoServicesRegistrar.setSecureRandom(FipsDRBG.SHA512_HMAC.fromEntropySource(new BasicEntropySourceProvider(new SecureRandom(), true)).build(null, false));
        // Criar o keystore no diretorio atual
        //KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        KeyStore ks = KeyStore.getInstance("BCFKS", "BCFIPS");
        // Cria do zero o keystore
        ks.load(null, null);
        // Armazena a senha mestre do keystore 
        Scanner input = new Scanner(System.in);
        System.out.println("Digite a senha mestra a ser utilizada: ");
        String keystoreSenha;
        keystoreSenha = input.nextLine();
        salt = obj.getSalt();
        senhaMestra = generateDerivedKey(keystoreSenha, salt, it);
        System.out.println("Senha entrada para o keystore = " + keystoreSenha);
        System.out.println("Senha derivada do keystore = " + senhaMestra);
        System.out.println("");
        ks.store(new FileOutputStream(keystoreFile), senhaMestra.toCharArray());
        // Gera chaves PBKDF2
        //Alice
        System.out.println("Digite uma senha para alice: ");
        String senhaDeAlice = input.nextLine();
        salt = obj.getSalt();
        System.out.println("Senha original de alice= " + senhaDeAlice);
        System.out.println("Sal gerado = " + salt);
        System.out.println("Numero de iteracoes = " + it);
        String chaveDerivadaDeAlice = generateDerivedKey(senhaDeAlice, salt, it);
        System.out.println("Chave derivada da senha = " + chaveDerivadaDeAlice);
        Key keyDeAlice = new SecretKeySpec(Hex.decodeHex(chaveDerivadaDeAlice.toCharArray()), "AES");
        System.out.println("");
        
        //bob
        System.out.println("Digite uma senha para bob: ");
        String senhaDeBob = input.nextLine();
        salt = obj.getSalt();
        System.out.println("Senha original de bob= " + senhaDeBob);
        System.out.println("Sal gerado = " + salt);
        System.out.println("Numero de iteracoes = " + it);
        String chaveDerivadaDeBob = generateDerivedKey(senhaDeBob, salt, it);
        System.out.println("Chave derivada da senha = " + chaveDerivadaDeBob);
        Key keyDeBob = new SecretKeySpec(Hex.decodeHex(chaveDerivadaDeBob.toCharArray()), "AES");
        System.out.println("");
        
        //ana
        System.out.println("Digite uma senha para ana: ");
        String senhaDeAna = input.nextLine();
        salt = obj.getSalt();
        System.out.println("Senha original de ana= " + senhaDeAna);
        System.out.println("Sal gerado = " + salt);
        System.out.println("Numero de iteracoes = " + it);
        String chaveDerivadaDeAna = generateDerivedKey(senhaDeAna, salt, it);
        System.out.println("Chave derivada da senha = " + chaveDerivadaDeAna);
        Key keyDeAna = new SecretKeySpec(Hex.decodeHex(chaveDerivadaDeAna.toCharArray()), "AES");
        System.out.println("");
        
        //pedro
        System.out.println("Digite uma senha para pedro: ");
        String senhaDePedro = input.nextLine();
        salt = obj.getSalt();
        System.out.println("Senha original de pedro= " + senhaDePedro);
        System.out.println("Sal gerado = " + salt);
        System.out.println("Numero de iteracoes = " + it);
        String chaveDerivadaDePedro = generateDerivedKey(senhaDePedro, salt, it);
        System.out.println("Chave derivada da senha = " + chaveDerivadaDePedro);
        Key keyDePedro = new SecretKeySpec(Hex.decodeHex(chaveDerivadaDePedro.toCharArray()), "AES");
        System.out.println("");
        
        ks.load(new FileInputStream(keystoreFile), senhaMestra.toCharArray());
        ks.setKeyEntry(alice.getNome(), keyDeAlice, senhaDeAlice.toCharArray(), null);
        ks.setKeyEntry(bob.getNome(), keyDeBob, senhaDeBob.toCharArray(), null);
        ks.setKeyEntry(ana.getNome(), keyDeAna, senhaDeAna.toCharArray(), null);
        ks.setKeyEntry(pedro.getNome(), keyDePedro, senhaDePedro.toCharArray(), null);
        ks.store(new FileOutputStream(keystoreFile), senhaMestra.toCharArray());
        
        //envio de mensagem
        System.out.println("Digite a mensagem a ser enviada  para Bob:");
        String mensagem = input.nextLine();
        cipher = Cipher.getInstance("AES/CTR/NoPadding");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keyDeAlice, ivSpec);
        String mensagemCifrada = Hex.encodeHexString(cipher.doFinal(mensagem.getBytes()));
        System.out.println("Chave de Alice \t= " + chaveDerivadaDeAlice);
        System.out.println("IV da mensagem \t= " + Hex.encodeHexString(iv));
        System.out.println("Mensagem Cifrada \t= " + mensagemCifrada);
        System.out.println("Mensagem Original \t= " + mensagem);
        System.out.println();
        
        enviarMensagem(mensagemCifrada, alice.getNome() ,senhaDeAlice);
        
    }
    
    public static String generateDerivedKey(String password, String salt, Integer iterations) {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), iterations, 128);
        SecretKeyFactory pbkdf2 = null;
        String derivedPass = null;
        try {
            pbkdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            SecretKey sk = pbkdf2.generateSecret(spec);
            derivedPass = Hex.encodeHexString(sk.getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return derivedPass;
    }

    private static void enviarMensagem(String mensagemCifrada,String nome ,String senha) throws KeyStoreException, NoSuchProviderException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, InvalidKeyException, InvalidAlgorithmParameterException, DecoderException, IllegalBlockSizeException, BadPaddingException {
        System.out.println("Bob recebe a mensagem...");
        KeyStore ks = KeyStore.getInstance("BCFKS", "BCFIPS");
        Key key;
        ks.load(new FileInputStream(keystoreFile), senhaMestra.toCharArray());
        key = ks.getKey(nome, senha.toCharArray());
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] embytes;
        embytes = Hex.decodeHex(mensagemCifrada.toCharArray());
        String decryptedString = new String(cipher.doFinal(embytes));
        System.out.println("Chave de Alice \t= " + Hex.encodeHexString(key.getEncoded()));
        System.out.println("IV da mensagem \t= " + Hex.encodeHexString(ivSpec.getIV()));
        System.out.println("Mensagem recebida \t= " + mensagemCifrada);
        System.out.println("Mensagem decifrada \t= " + decryptedString);
    }
    
    /*Usado para gerar o salt  */
    public String getSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        //SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return Hex.encodeHexString(salt);
    }
}

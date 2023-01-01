package com.duwei.cp.abe.util;

import com.duwei.cp.abe.parameter.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.*;
import java.nio.file.Files;
import java.util.Base64;
import java.util.Properties;

//储存systemKey
public class FileStoreUtils {

    private static String PK_name="PublicKey.properties";
    private static String MSK_name="MasterPrivateKey.properties";
    public static void storeSystemKey(String filePath, SystemKey key) throws IOException {
        storePublicKey(filePath,key.getPublicKey());
        storeMasterPrivateKey(filePath,key.getMasterPrivateKey());
    }

    public static SystemKey getSystemKey(String filePath) throws IOException {
        SystemKey systemKey = SystemKey.getInstance();
        MasterPrivateKey msk = getMasterPrivateKey(filePath);
        systemKey.setPublicKey(getPublicKey(filePath,msk));
        systemKey.setMasterPrivateKey(msk);
        return systemKey;
    }


    private static void storePublicKey(String filePath, PublicKey key) throws IOException {
        String path = System.getProperty("user.dir")+ filePath;
        File pathFile = new File(path);
        if (!pathFile.exists()) {
            pathFile.mkdirs();
        }
        File PK_File = new File(path + PK_name);
        if(!PK_File.exists()){
            PK_File.createNewFile();
        }
        Properties properties = new Properties();
        properties.load(Files.newInputStream(PK_File.toPath()));

//        Element h = key.getH().getImmutable();
//        Element egg_a = key.getEgg_a().getImmutable();
//        Element f = key.getF().getImmutable();
        Element generator = key.getPairingParameter().getGenerator().getImmutable();

//        properties.setProperty("h", Base64.getEncoder().withoutPadding().encodeToString(h.toBytes()));
//        properties.setProperty("egg_a",Base64.getEncoder().withoutPadding().encodeToString(egg_a.toBytes()));
//        properties.setProperty("f",Base64.getEncoder().withoutPadding().encodeToString(f.toBytes()));
        properties.setProperty("generator",Base64.getEncoder().withoutPadding().encodeToString(generator.toBytes()));

        properties.store(Files.newOutputStream(PK_File.toPath()), "UTF-8");

    }

    private static void storeMasterPrivateKey(String filePath, MasterPrivateKey key) throws IOException {
        String path = System.getProperty("user.dir")+ filePath;
        File pathFile = new File(path);
        if (!pathFile.exists()) {
            pathFile.mkdirs();
        }
        File MSK_File = new File(path + MSK_name);
        if(!MSK_File.exists()){
            MSK_File.createNewFile();
        }
        Properties properties = new Properties();
        properties.load(Files.newInputStream(MSK_File.toPath()));

        Element beta = key.getBeta().getImmutable();
//        Element g_alpha = key.getG_alpha().getImmutable();
        Element alpha = key.getAlpha().getImmutable();
        Element generator = key.getPairingParameter().getGenerator().getImmutable();

        properties.setProperty("beta", Base64.getEncoder().withoutPadding().encodeToString(beta.toBytes()));
//        properties.setProperty("g_alpha", Base64.getEncoder().withoutPadding().encodeToString(g_alpha.toBytes()));
        properties.setProperty("alpha", Base64.getEncoder().withoutPadding().encodeToString(alpha.toBytes()));
        properties.setProperty("generator", Base64.getEncoder().withoutPadding().encodeToString(generator.toBytes()));

        properties.store(Files.newOutputStream(MSK_File.toPath()), "UTF-8");
    }

    private static PublicKey getPublicKey(String filePath,MasterPrivateKey msk) throws IOException {
        String path = System.getProperty("user.dir")+ filePath+PK_name;
        File PK_File = new File(path);
        if(!PK_File.exists()){
            throw new RuntimeException("PublicKey文件不存在!");
        }
        Properties properties = new Properties();
        properties.load(Files.newInputStream(PK_File.toPath()));
//        String s_h = (String) properties.get("h");
//        String s_egg_a = (String) properties.get("egg_a");
//        String s_f = (String) properties.get("f");
        String s_generator = (String) properties.get("generator");

        PairingParameter parameter = getPairingParameter(s_generator);

        return PublicKey.build(parameter,msk);
    }

    private static MasterPrivateKey getMasterPrivateKey(String filePath) throws IOException {
        String path = System.getProperty("user.dir")+ filePath+MSK_name;
        File MSK_File = new File(path);
        if(!MSK_File.exists()){
            throw new RuntimeException("MasterPrivateKey文件不存在!");
        }
        Properties properties = new Properties();
        properties.load(Files.newInputStream(MSK_File.toPath()));

        String s_beta = (String) properties.get("beta");
        String s_alpha = (String) properties.get("alpha");
        String s_generator = (String) properties.get("generator");

        PairingParameter parameter = getPairingParameter(s_generator);

        MasterPrivateKey masterPrivateKey = new MasterPrivateKey(parameter);
        masterPrivateKey.setBeta(parameter.getZr().newElementFromBytes(Base64.getDecoder().decode(s_beta)).getImmutable());
        masterPrivateKey.setAlpha(parameter.getZr().newElementFromBytes(Base64.getDecoder().decode(s_alpha)).getImmutable());
        masterPrivateKey.setG_alpha(parameter.getGenerator().powZn(masterPrivateKey.getAlpha()).getImmutable());

        return masterPrivateKey;
    }

    private static PairingParameter getPairingParameter(String s_generator){
        Pairing pairing = PairingFactory.getPairing(PairingParameter.parametersPath);
        PairingParameter parameter = new PairingParameter();
        parameter.setPairing(pairing);
        parameter.setG0(pairing.getG1());
        parameter.setG1(pairing.getGT());
        parameter.setZr(pairing.getZr());
        parameter.setGenerator(parameter.getG0().newElementFromBytes(Base64.getDecoder().decode(s_generator)).getImmutable());
        return parameter;
    }

}

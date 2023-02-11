import com.duwei.cp.abe.attribute.Attribute;
import com.duwei.cp.abe.engine.CpAneEngine;
import com.duwei.cp.abe.parameter.PublicKey;
import com.duwei.cp.abe.parameter.SystemKey;
import com.duwei.cp.abe.parameter.UserPrivateKey;
import com.duwei.cp.abe.structure.AccessTree;
import com.duwei.cp.abe.structure.AccessTreeBuildModel;
import com.duwei.cp.abe.text.CipherText;
import com.duwei.cp.abe.text.PlainText;
import com.duwei.cp.abe.util.FileStoreUtils;
import com.duwei.cp.abe.util.ObjectConvertUtil;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.IOException;
import java.util.*;

import static com.duwei.cp.abe.parameter.PairingParameter.parametersPath;

public class Test {

    @org.junit.Test
    public void setUp() throws IOException {
        SystemKey systemKey = SystemKey.build();
        FileStoreUtils.storeSystemKey("/key/", systemKey);
    }

    @org.junit.Test
    public void getKey() throws IOException {
        SystemKey systemKey = FileStoreUtils.getSystemKey("/key/");
        System.out.println(systemKey);

    }

    @org.junit.Test
    public void convert() throws IOException {
        CpAneEngine cpAneEngine = new CpAneEngine();
        SystemKey systemKey = FileStoreUtils.getSystemKey("/key/");
        String plainTextStr = "你好，CP - ABE，我是JPBC";
        PlainText plainText = new PlainText(plainTextStr, systemKey.getPublicKey());
        AccessTree accessTree = getAccessTree(systemKey.getPublicKey());
        CipherText cipherText = cpAneEngine.encrypt(systemKey.getPublicKey(), plainText, accessTree);
        System.out.println("cipherText : " + cipherText);
        Optional<byte[]> bytes = ObjectConvertUtil.objectToBytes(cipherText);
        bytes.ifPresent(value -> {
            String s = Base64.getEncoder().withoutPadding().encodeToString(value);
            System.out.println(s);
        });
    }

    public static AccessTree getAccessTree(PublicKey publicKey) {
        AccessTreeBuildModel[] accessTreeBuildModels = new AccessTreeBuildModel[4];
        //根节点ID必须为1
        accessTreeBuildModels[0] = AccessTreeBuildModel.innerAccessTreeBuildModel(1, 1, 1, -1);
        accessTreeBuildModels[1] = AccessTreeBuildModel.leafAccessTreeBuildModel(2, 4, "1", 1);
        accessTreeBuildModels[2] = AccessTreeBuildModel.leafAccessTreeBuildModel(3, 2, "2", 1);
        accessTreeBuildModels[3] = AccessTreeBuildModel.leafAccessTreeBuildModel(4, 3, "3", 1);
        return AccessTree.build(publicKey, accessTreeBuildModels);
    }

    @org.junit.Test
    public void testToByte() {
        Map<String, Object> map = new HashMap<>();
        map.put("haha", "1");
        map.put("xixxi", "23");
        Optional<byte[]> bytes = ObjectConvertUtil.objectToBytes(map);
        bytes.ifPresent(value -> {
            String s = Base64.getEncoder().withoutPadding().encodeToString(value);
            System.out.println(s);
        });
    }

    @org.junit.Test
    public void testToObject() {

        String s = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAADdAADaGhhdXIAAltCrPMX+AYIVOACAAB4cAAAAAQAAQABdAAEaGFoYXQAATF0AAV4aXh4aXQAAjIzeA";
        Map<String, Object> map = ObjectConvertUtil.base64ToObject(s);
        byte[] b = (byte[]) map.get("hha");
        System.out.println(new String(b));
    }

    @org.junit.Test
    public void test2() throws IOException {
        CpAneEngine cpAneEngine = new CpAneEngine();
        SystemKey systemKey = FileStoreUtils.getSystemKey("/key/");
        String plainTextStr = "你好，CP - ABE，我是JPBC";
        PlainText plainText = new PlainText(plainTextStr, systemKey.getPublicKey());
        AccessTree accessTree = getAccessTree(systemKey.getPublicKey());
        CipherText cipherText = cpAneEngine.encrypt(systemKey.getPublicKey(), plainText, accessTree);
        Pairing pairing = PairingFactory.getPairing(parametersPath);
        List<Attribute> attributes = Arrays.asList(
                // new Attribute("学生", systemKey.getPublicKey()),
                //new Attribute("老师", systemKey.getPublicKey()),
                new Attribute("1", systemKey.getPublicKey())
                // new Attribute("二班", systemKey.getPublicKey())
        );
        UserPrivateKey userPrivateKey = cpAneEngine.keyGen(systemKey.getMasterPrivateKey(), attributes);

        String s = cipherText.toStr(systemKey);
        System.out.println(s);
        CipherText cipherText1 = CipherText.fromStr(s, systemKey);
        System.out.println(cipherText);
        System.out.println(cipherText1);

        cipherText.getAccessTree().getRoot().setSecretNumber(null);
        String decryptStr = cpAneEngine.decryptToStr(systemKey.getPublicKey(), userPrivateKey, cipherText1);
        System.out.println(decryptStr);

//                Element c_wave = cipherText.getC_wave().getImmutable();
//        System.out.println(c_wave);
//        byte[] bytes = c_wave.toBytes();
//        Element element = pairing.getGT().newElementFromBytes(bytes);
//        System.out.println(element);
//        System.out.println(c_wave.isEqual(element));

//        Element c = cipherText.getC().getImmutable();
//        System.out.println(c);
//        byte[] bytes = c.toBytes();
//        Element element = pairing.getG1().newElementFromBytes(bytes);
//        System.out.println(element);
//        System.out.println(element.isEqual(c));

//        Map<Attribute, Element> c_y_map = cipherText.getC_y_pie_map();
//        for (Map.Entry<Attribute, Element> entry : c_y_map.entrySet()) {
//            Element value = entry.getValue().getImmutable();
//            System.out.println(value);
//            byte[] bytes = value.toBytes();
//            Element element = pairing.getG1().newElementFromBytes(bytes);
//            System.out.println(element);
//            System.out.println(element.isEqual(value));
//        }

//        AccessTreeNode root = cipherText.getAccessTree().getRoot();
//        Element element = root.getSecretNumber().getImmutable();
//        System.out.println(element);
//        byte[] bytes = element.toBytes();
//        Element immutable = pairing.getZr().newElementFromBytes(bytes).getImmutable();
//        System.out.println(immutable);
//        System.out.println(element.isEqual(immutable));

//        AccessTree accessTree1 = cipherText.getAccessTree();
//        Map<Integer, byte[]> leafSecretNumber = accessTree1.getLeafSecretNumber();
//        System.out.println(leafSecretNumber);
    }

    @org.junit.Test
    public void encrypt() throws IOException {
        CpAneEngine cpAneEngine = new CpAneEngine();
        SystemKey systemKey = FileStoreUtils.getSystemKey("/key/");
        String plainTextStr = "你好，CP - ABE，我是JPBC";
        PlainText plainText = new PlainText(plainTextStr, systemKey.getPublicKey());
        AccessTree accessTree = getAccessTree(systemKey.getPublicKey());
        CipherText cipherText = cpAneEngine.encrypt(systemKey.getPublicKey(), plainText, accessTree);
        System.out.println(cipherText.toStr(systemKey));
    }

    @org.junit.Test
    public void decrypt() throws IOException {
        String s = "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";
        CpAneEngine cpAneEngine = new CpAneEngine();
        SystemKey systemKey = FileStoreUtils.getSystemKey("/key/");
        List<Attribute> attributes = Arrays.asList(
                // new Attribute("学生", systemKey.getPublicKey()),
                //new Attribute("老师", systemKey.getPublicKey()),
                new Attribute("1", systemKey.getPublicKey())
                // new Attribute("二班", systemKey.getPublicKey())
        );
        UserPrivateKey userPrivateKey = cpAneEngine.keyGen(systemKey.getMasterPrivateKey(), attributes);
        CipherText cipherText1 = CipherText.fromStr(s, systemKey);
        String decryptStr = cpAneEngine.decryptToStr(systemKey.getPublicKey(), userPrivateKey, cipherText1);
        System.out.println(decryptStr);
    }
}

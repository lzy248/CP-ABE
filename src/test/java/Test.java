import com.duwei.cp.abe.attribute.Attribute;
import com.duwei.cp.abe.engine.CpAneEngine;
import com.duwei.cp.abe.parameter.PublicKey;
import com.duwei.cp.abe.parameter.SystemKey;
import com.duwei.cp.abe.parameter.UserPrivateKey;
import com.duwei.cp.abe.structure.AccessTree;
import com.duwei.cp.abe.structure.AccessTreeBuildModel;
import com.duwei.cp.abe.structure.AccessTreeNode;
import com.duwei.cp.abe.text.CipherText;
import com.duwei.cp.abe.text.PlainText;
import com.duwei.cp.abe.util.FileStoreUtils;
import com.duwei.cp.abe.util.ObjectConvertUtil;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
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
    public void testToByte() throws UnsupportedEncodingException {
        Map<String,Object> map = new HashMap<>();
        map.put("haha","1");
        map.put("xixxi","23");
        Optional<byte[]> bytes = ObjectConvertUtil.objectToBytes(map);
        bytes.ifPresent(value -> {
            String s = Base64.getEncoder().withoutPadding().encodeToString(value);
            System.out.println(s);
        });
    }
    @org.junit.Test
    public void testToObject(){

        String s = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAADdAADaGhhdXIAAltCrPMX+AYIVOACAAB4cAAAAAQAAQABdAAEaGFoYXQAATF0AAV4aXh4aXQAAjIzeA";
        Map<String,Object> map = ObjectConvertUtil.base64ToObject(s);
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

        String s = cipherText.toStr();
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
        System.out.println(cipherText.toStr());
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

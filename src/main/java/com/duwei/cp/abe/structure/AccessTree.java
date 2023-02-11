package com.duwei.cp.abe.structure;


import com.duwei.cp.abe.parameter.PublicKey;
import com.duwei.cp.abe.text.SerializableElement;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import lombok.Data;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @BelongsProject: JPBC-ABE
 * @BelongsPackage: com.duwei.jpbc.cp.abe.structure
 * @Author: duwei
 * @Date: 2022/7/21 17:07
 * @Description: 访问树结构
 */
@Data
public class AccessTree {
    private AccessTreeNode root;
    private AccessTreeBuildModel[] accessTreeBuildModels;

    private AccessTree(AccessTreeNode root, AccessTreeBuildModel[] accessTreeBuildModels) {
        this.root = root;
        this.accessTreeBuildModels = accessTreeBuildModels;
    }

    public Map<Integer, SerializableElement> getLeafSecretNumber(Pairing pairing) {
        HashMap<Integer, SerializableElement> map = new HashMap<>();
        getLeaf(root, map, pairing);
        return map;
    }

    private void getLeaf(AccessTreeNode node, Map<Integer, SerializableElement> map, Pairing pairing) {
        if (node instanceof LeafAccessTreeNode) {
            LeafAccessTreeNode leaf = (LeafAccessTreeNode) node;
            map.put(leaf.getIndex(), SerializableElement.fromElement(leaf.getSecretNumber(), pairing));
        } else if (node instanceof InnerAccessTreeNode) {
            for (AccessTreeNode child : node.getChildren()) {
                getLeaf(child, map, pairing);
            }
        }
    }

    public void setLeafSecretNumber(Map<Integer, SerializableElement> map, Pairing pairing) {
        setLeaf(root, map, pairing);
    }

    private void setLeaf(AccessTreeNode node, Map<Integer, SerializableElement> map, Pairing pairing) {
        if (node instanceof LeafAccessTreeNode) {
            SerializableElement serializableElement = map.get(node.getIndex());
            Element secretNumber = serializableElement.toElement(pairing);
            node.setSecretNumber(secretNumber);
        } else if (node instanceof InnerAccessTreeNode) {
            for (AccessTreeNode child : node.getChildren()) {
                setLeaf(child, map, pairing);
            }
        }
    }

//    /**
//     * 构建访问树节点
//     *
//     * @return
//     */
//    public static AccessTree build(PublicKey publicKey) {
//        AccessTreeNode root = new InnerAccessTreeNode(2, 1, null);
//        List<AccessTreeNode> children = new ArrayList<>();
//        children.add(new LeafAccessTreeNode("学生", publicKey, root, 1));
//        children.add(new LeafAccessTreeNode("老师", publicKey, root, 2));
//        children.add(new LeafAccessTreeNode("硕士", publicKey, root, 3));
//        root.setChildren(children);
//        return new AccessTree(root);
//    }


    public static AccessTree build(PublicKey publicKey, AccessTreeBuildModel[] accessTreeBuildModels) {
        Map<Integer, AccessTreeNode> idNodeMap = new HashMap<>();
        for (int i = 0; i < accessTreeBuildModels.length; i++) {
            AccessTreeBuildModel model = accessTreeBuildModels[i];
            AccessTreeNode node = null;
            if (model.getType() == AccessTreeNodeType.INNER_NODE) {
                //内部节点
                node = new InnerAccessTreeNode(model.getThreshold(), model.getIndex());
            } else if (model.getType() == AccessTreeNodeType.LEAF_NODE) {
                //叶子节点
                node = new LeafAccessTreeNode(model.getAttribute(), publicKey, model.getIndex());
            }
            node.setParentId(model.getParentId());
            idNodeMap.put(model.getId(), node);
        }
        //父亲节点ID  -  集合
        Map<Integer, List<AccessTreeNode>> collect = idNodeMap.values().stream().collect(Collectors.groupingBy(AccessTreeNode::getParentId));
        idNodeMap.forEach((id, node) -> {
            List<AccessTreeNode> accessTreeNodes = collect.get(id);
            if (accessTreeNodes != null) {
                node.setChildren(accessTreeNodes);
                accessTreeNodes.forEach((child) -> child.setParent(node));
            }
        });

        //根节点元素索引必须为1
        return new AccessTree(idNodeMap.get(1), accessTreeBuildModels);
    }
}

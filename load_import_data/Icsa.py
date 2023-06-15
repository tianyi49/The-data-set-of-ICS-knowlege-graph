import os
import json
import re
import xml.dom.minidom
from py2neo import Graph,Node,Relationship, Subgraph
from bs4 import BeautifulSoup
import time
class SecurityGraph:
    def __init__(self):
        cur_dir = '/'.join(os.path.abspath(__file__).split('\\')[:-1])
        self.g = Graph("http://localhost:7474", auth=("neo4j", "tianyi49"), name='neo4j')
    '''找到"xml文件中的子节点的所有文本(深度优先搜索）'''
    def extract_xml_childtexts(self,xml_tag,textlist):
        """获得标签下的全部信息"""
        if xml_tag.nodeType == 3:  # TEXT 标签
            textlist.append(xml_tag.data.strip())
        for child_tag in xml_tag.childNodes:
            self.extract_xml_childtexts(child_tag,textlist)

    '''处理嵌套列表中的重复元素'''
    def setList(self,rawlist):
        new_list = [list(t) for t in set(tuple(_) for _ in rawlist)]
        return new_list

    '''读取ICSA数据集'''
    def read_icsa(self):
        alllist=[]            # [节点，关系]
        ics_id=[]            #唯一约束ID 格式【id,title]
        ics_equipment=[]
        ics_vul=[]
        ics_vul_description=[]
        ics_attention=[]
        ics_vendor=[]
        ics_mitigation=[]
        ics_risk=[]
        #构建节点实体关系默认为与icsa_ID的关系
        rels_equipment=[]
        rels_vul=[]
        rels_vul_cwe=[]
        rels_description=[]
        rels_cve=[]
        rels_attention=[]
        rels_equipment_vendor=[]
        rels_mitigation=[]
        rels_risk=[]
        counttotal = 0
        with open("../data/icscert1.json",encoding='utf-8') as f:
            dict1 = json.load(f)
            for key in dict1:
                ics_item=dict1[key]
                counttotal+= 1  # 漏洞数量计算
                try:
                    ics_title=ics_item["ics_title"]
                except:
                    ics_title=''
                ics_id.append([key,ics_title])
                try:
                    ics_equipment.append(ics_item["ics_equipment"])
                    rels_equipment.append([key,ics_item["ics_equipment"]])
                    try:
                        ics_vendor.append(ics_item["ics_vendor"])
                        rels_equipment_vendor.append([ics_item["ics_equipment"], ics_item["ics_vendor"]])
                    except:
                        pass
                except:
                    pass
                try:
                    for vul_item in ics_item["ics_vul"]:
                        ics_vul.append(vul_item["ics_vul"])
                        rels_vul.append([key,vul_item["ics_vul"]])
                        try:
                            ics_vul_description.append(vul_item["ics_description"])
                            rels_description.append([key,vul_item["ics_description"]])
                        except:
                            pass
                        try:
                            rels_vul_cwe.append([vul_item["ics_vul"],vul_item["ics_relate_cwe"]])
                        except:
                            pass
                except:
                    pass
                try:
                    ics_attention.append(ics_item["ics_attention"])
                    rels_attention.append([key, ics_item["ics_attention"]])
                except:
                    pass
                try:
                    ics_mitigation.append(ics_item["ics_mitigation"])
                    rels_mitigation.append([key, ics_item["ics_mitigation"]])
                except:
                    pass
                try:
                    ics_risk.append(ics_item["ics_risk"])
                    rels_risk.append([key, ics_item["ics_risk"]])
                except:
                    pass
                try:
                    for cveitem in ics_item["ics_relate_cve"]:
                        rels_cve.append([key,cveitem])
                except:
                    pass
            f.close()
        print("***************总共有%d条漏洞" % counttotal)
        alllist.append([self.setList(ics_id),set(ics_equipment),set( ics_vul),set( ics_vul_description),set( ics_attention),set( ics_vendor),set( ics_mitigation),set( ics_risk)])
        alllist.append([self.setList(rels_equipment ),self.setList(rels_vul ),self.setList( rels_vul_cwe ),self.setList( rels_description ),self.setList( rels_cve ),self.setList( rels_attention ),self.setList( rels_equipment_vendor ),self.setList( rels_mitigation ),self.setList( rels_risk )])
        return alllist

    def create_nodeslist(self,alllist):
        allnodelist=[]
        nodedict= {}
        ics_id, ics_equipment, ics_vul, ics_vul_description, ics_attention, ics_vendor, ics_mitigation, ics_risk = alllist[0]
       #icsa节点建立
        print("开始创建节点：icsa")
        nodedict["ics_id"]=self.create_node('ics_id',ics_id)
        nodedict["product"] = self.create_node('product', ics_equipment)
        nodedict["ics_vul"] = self.create_node('ics_vul', ics_vul)
        nodedict["description"] = self.create_node('description', ics_vul_description)
        nodedict["ics_attention"] = self.create_node('ics_attention', ics_attention)
        nodedict["vendor"] = self.create_node('vendor', ics_vendor)
        nodedict["mitigation"] = self.create_node('mitigation', ics_mitigation)
        nodedict["consequence"] = self.create_node('consequence', ics_risk)
        for key in nodedict:
            for key1 in nodedict[key]:
                    allnodelist.append(nodedict[key][key1])
        print('***************nodelist创建完成***************')
        return  nodedict,allnodelist

    def create_relationshiplist(self,alllist,nodedict):
        allrelationlist=[]
        rels_equipment , rels_vul , rels_vul_cwe , rels_description , rels_cve , rels_attention , rels_equipment_vendor , rels_mitigation , rels_risk=alllist[1]
        print("***************开始创建cve关系***************")
        allrelationlist += self.create_relationship('ics_id', 'product', rels_equipment, 'impact_product', nodedict)
        allrelationlist += self.create_relationship('ics_id', 'ics_vul', rels_vul, 'has_vul', nodedict)
        allrelationlist += self.create_relationship('ics_vul', 'cwe_id', rels_vul_cwe, 'relate_cwe', nodedict)
        allrelationlist += self.create_relationship('ics_id', 'description', rels_description, 'has_description', nodedict)
        allrelationlist += self.create_relationship('ics_id', 'cve_id', rels_cve, 'relate_cve', nodedict)
        allrelationlist += self.create_relationship('ics_id', 'ics_attention', rels_attention, 'has_attention', nodedict)
        allrelationlist += self.create_relationship('product', 'vendor', rels_equipment_vendor, 'has_vendor', nodedict)
        allrelationlist += self.create_relationship('ics_id', 'mitigation', rels_mitigation, 'has_mitigation', nodedict)
        allrelationlist += self.create_relationship('ics_id', 'consequence', rels_risk, 'has_consequence', nodedict)
        return allrelationlist
    def create_node(self, label, nodes):
        nodes=list(nodes)
        nodes_dict = {} # 一批节点数据
        if(isinstance(nodes[0],list)==0):
            for node_name in nodes:
                node = Node(label, name=node_name)
                nodes_dict[node['name']]=node
        else:
            if (label == 'com5g_id'):
                propertylist = ['title']
                for node_name in nodes:
                    node=Node(label, name=node_name[0],title=node_name[1])
                    nodes_dict[node['name']]=node
        return   nodes_dict
            #self.batch_create(nodes_list,[])
            #'''注释为低速不重复导入方法'''
            # if (isinstance(nodes[0], list) == 0):
            #     for node_name in nodes:
            #         query1 = "merge(p:%s{name:'%s'})" % (label, node_name)
            #         self.g.run(query1)
            #         count += 1
            #         print(count, label, len(nodes))
            # else:
            #     query1 = "merge(p:%s{name:'%s'})" % (label, node_name[0])
            #     self.g.run(query1)
            #     #对属性的单独处理
            #     if(label=='cve_id'):
            #       propertylist=['description']
            #     elif(label=='capec_id'):
            #       propertylist=['title','abstraction','description']
            #     elif(label=='cwe_id'):
            #       propertylist=['title','abstraction','description','extend_description']
            #     elif(label=='attack_step'):
            #       propertylist=['step']
            #     elif (label == 'skills_required'):
            #       propertylist = ['level']
            #     pnode = self.g.nodes.match(label, name=node_name[0]).first()
            #     for i in range(1,len(node_name)):
            #         pnode.update({propertylist[i-1]: node_name[i]})
            #         # query2 = "match(p:%s{name:'%s'}) set p.%s=r'%s' "% (label, node_name[0],propertylist[i-1],node_name[i])
            #         # self.g.run(query2)
            #     self.g.push(pnode)
            #     count += 1
            #     print(count, label,len(nodes))

        return
    def create_relationship(self, start_node, end_node, edges, rel_type,nodedict):
        relations_list = []  # 一批关系数据:
        for edge in edges:
            try:
                if(isinstance(edge[1],list)==1):
                    pnode = nodedict[start_node][edge[0]]
                    qnode = nodedict[end_node][edge[1][0]]
                elif(isinstance(edge[0],list)==1):
                    pnode = nodedict[start_node][edge[0][0]]
                    if(rel_type=="relate_cve"):
                        qnode = self.g.nodes.match(end_node, name=edge[1]).first()
                    else:
                        qnode = nodedict[end_node][edge[1]]
                elif(rel_type=="relate_cwe"):
                    pnode = nodedict[start_node][edge[0]]
                    qnode = self.g.nodes.match(end_node, name=edge[1]).first()
                elif(rel_type=="relate_cve"):
                    pnode = nodedict[start_node][edge[0]]
                    qnode = self.g.nodes.match(end_node, name=edge[1]).first()
                else:
                    pnode= nodedict[start_node][edge[0]]
                    qnode= nodedict[end_node][edge[1]]
                relation = Relationship(pnode, rel_type, qnode)
                relations_list.append(relation)
            except:
                pass
        return relations_list
        print(('***************relationlist:%s创建完成***************')%rel_type)

    def batch_create(self, nodes_list, relations_list,num):
        """
            批量创建节点/关系,nodes_list和relations_list不同时为空即可
            特别的：当利用关系创建节点时，可使得nodes_list=[]
        :param graph: Graph()
        :param nodes_list: Node()集合
        :param relations_list: Relationship集合
        :return:
        """
        nodebacth=int(len(nodes_list)/num);relationbatch=int(len(relations_list)/num)
        tx_ = self.g.begin()
        for i in range(0,num):
            print('第%d次创建子图' % (i + 1), num)
            subgraph = Subgraph(nodes_list[nodebacth*i:nodebacth*(i+1)-1], relations_list[relationbatch*i:relationbatch*(i+1)-1])
            tx_.create(subgraph)
        print('***************事务提交中***************')
        tx_.commit()
    def crate_indexs(self,property):
        """
        对每个标签的property创建索引
        """
        for label in handler.g.schema.node_labels:
            try:
                query = " CREATE INDEX ON :%s(%s)" %(label,property)
                self.g.run(query)
            except:
                pass
    def drop_indexs(self):
        """
        删除所有索引
        """
        try:
            query = " CALL apoc.schema.assert({},{},true) YIELD label, key RETURN *"
            self.g.run(query)
        except:
            pass
    def delete_repeat_nodes(self):
        """
        对每个标签的property删除重复节点
        """
        for label in handler.g.schema.node_labels:
            if(label=='attack_step' or label== "skills_required"):
                continue
            query = " MATCH (n:%s) WITH n.name AS nmae, collect(n) AS nodes WHERE size(nodes) > 1 FOREACH (n in tail(nodes) | DETACH DELETE n)" % label
            self.g.run(query)
    def update_index(self):
        self.drop_indexs()
        self.crate_indexs('name')
        print('index已更新')
    def merge_repeat_nodes(self):
        """
        融合重复节点
        """
        for label in handler.g.schema.node_labels:
            if(label=='attack_step' or label== "skills_required"):
                continue
            query = "MATCH (n:%s) WITH n.name AS name, COLLECT(n) AS nodelist, COUNT(*) AS count " \
                    "WHERE count > 1 " \
                    "CALL apoc.refactor.mergeNodes(nodelist) YIELD node RETURN node"%label
            self.g.run(query)
    def read_com5g(self):
        alllist=[]
        #节点
        com5g_id=[['Com5G-1-1','Access authentication failure'],['Com5G-2-1','Destruction of data integrity'],['Com5G-3-1','Illegal control of NFs'],['Com5G-3-2','Malicious consumption of shared slicing resources']]  #格式[id,title]
        com5g_equip=['接入网','承载网','核心网']
        com5g_description=['5G通信网络存在接入认证失败漏洞，远程攻击者通过利用该漏洞实现对网络的非法入侵',"5G通信网络存在数据完整性破坏漏洞，非法入侵成功的攻击者通过对承载网发起拒绝服务、欺骗等攻击以干扰正常数据的通信传输。",'5G通信网络存在功能网元非法控制漏洞，攻击者利用支持核心网的基础资源设施漏洞以获取网元配置文件等敏感信息，最终实现网元的非法控制。','5G通信网络存在共享切片资源恶意竞争漏洞，非法入侵成功的攻击者通过不断向某一切片发起拒绝服务攻击以恶意消耗切片的共享资源，导致多业务场景无法正常通信。']
        #关系
        rels_equip=[[com5g_id[0][0],'接入网'],[com5g_id[1][0],'承载网'],[com5g_id[2][0],'核心网'],[com5g_id[3][0],'核心网']]
        rels_description = [[com5g_id[0][0],com5g_description[0]],[com5g_id[1][0],com5g_description[1]],[com5g_id[2][0],com5g_description[2]],[com5g_id[3][0],com5g_description[3]]]
        rels_severity = [[com5g_id[0][0],'HIGH'],[com5g_id[1][0],'HIGH'],[com5g_id[2][0],'MEDIUM'],[com5g_id[3][0],'HIGH']]
        rels_confidentialityImpact=[[com5g_id[0][0],'HIGH'],[com5g_id[1][0],'HIGH'],[com5g_id[2][0],'HIGH'],[com5g_id[3][0],'HIGH']]
        rels_integrityImpact = [[com5g_id[0][0],'LOW'],[com5g_id[1][0],'HIGH'],[com5g_id[2][0],'LOW'],[com5g_id[3][0],'HIGH']]
        rels_availabilityImpact = [[com5g_id[0][0],'LOW'],[com5g_id[1][0],'HIGH'],[com5g_id[2][0],'HIGH'],[com5g_id[3][0],'HIGH']]
        rels_publishedDate = [[com5g_id[0][0],'2021-12-30'],[com5g_id[1][0],'2021-12-30'],[com5g_id[2][0],'2021-12-30'],[com5g_id[3][0],'2021-12-30']]
        rels_attackvector = [[com5g_id[0][0],'NETWORK'],[com5g_id[0][0],'NETWORK'],[com5g_id[0][0],'NETWORK'],[com5g_id[0][0],'NETWORK']]
        rels_attackComplexity = [[com5g_id[0][0],'LOW'],[com5g_id[1][0],'LOW'],[com5g_id[2][0],'MEDIUM'],[com5g_id[3][0],'LOW']]
        rels_privilegesRequired = [[com5g_id[0][0],'HIGH'],[com5g_id[1][0],'NONE'],[com5g_id[2][0],'LOW'],[com5g_id[3][0],'NONE']]
        alllist.append([com5g_id,com5g_equip,com5g_description])
        alllist.append([rels_equip,rels_description,rels_severity,rels_confidentialityImpact,rels_integrityImpact,rels_availabilityImpact,rels_publishedDate,rels_attackvector,rels_attackComplexity,rels_privilegesRequired])
        return alllist
    def create_com5g_nodeslist(self,alllist):
        allnodelist=[]
        nodedict= {}
        com5g_id, com5g_equip, com5g_description= alllist[0]
        print("开始创建节点：com5g_id")
        nodedict["com5g_id"]=self.create_node('com5g_id',com5g_id)
        nodedict["com5g_equip"] = self.create_node('product', com5g_equip)
        nodedict["com5g_description"] = self.create_node('description', com5g_description)
        for key in nodedict:
            for key1 in nodedict[key]:
                allnodelist.append(nodedict[key][key1])
        return nodedict, allnodelist
    def create_relationship_com5g_list(self,alllist,nodedict):
        allrelationlist = []
        rels_equip, rels_description, rels_severity, rels_confidentialityImpact, rels_integrityImpact, rels_availabilityImpact, rels_publishedDate, rels_attackvector, rels_attackComplexity, rels_privilegesRequired=alllist[1]
        print("***************开始创建com5g关系***************")
        allrelationlist += self.create_com5g_relationship('com5g_id', 'com5g_equip', rels_equip, 'impact_product', nodedict)
        allrelationlist += self.create_com5g_relationship('com5g_id', 'com5g_description', rels_description, 'has_description', nodedict)
        allrelationlist += self.create_com5g_relationship('com5g_id', 'severity', rels_severity, 'has_impact', nodedict)
        allrelationlist += self.create_com5g_relationship('com5g_id', 'confidentiality_impact', rels_confidentialityImpact, 'has_imapct', nodedict)
        allrelationlist += self.create_com5g_relationship('com5g_id', 'integrity_impact', rels_integrityImpact, 'has_imapct', nodedict)
        allrelationlist += self.create_com5g_relationship('com5g_id', 'availability_impact', rels_availabilityImpact, 'has_imapct', nodedict)
        allrelationlist += self.create_com5g_relationship('com5g_id', 'published_date', rels_publishedDate, 'has_date', nodedict)
        allrelationlist += self.create_com5g_relationship('com5g_id', 'attack_vector', rels_attackvector, 'has_vector', nodedict)
        allrelationlist += self.create_com5g_relationship('com5g_id', 'attack_complexity', rels_attackComplexity, 'has_complexity', nodedict)
        allrelationlist += self.create_com5g_relationship('com5g_id', 'privileges_required', rels_privilegesRequired, 'has_require', nodedict)
        return allrelationlist
    def create_com5g_relationship(self, start_node, end_node, edges, rel_type,nodedict):
        relations_list = []  # 一批关系数据:
        for edge in edges:
            try:
                if (rel_type == "impact_product"):
                    pnode = nodedict[start_node][edge[0]]
                    qnode = nodedict[end_node][edge[1]]
                elif (rel_type == "has_description"):
                    pnode = nodedict[start_node][edge[0]]
                    qnode = nodedict[end_node][edge[1]]
                else:
                    pnode = nodedict[start_node][edge[0]]
                    qnode = self.g.nodes.match(end_node, name=edge[1]).first()
                relation = Relationship(pnode, rel_type, qnode)
                relations_list.append(relation)
            except:
                pass
        print(('***************relationlist:%s创建完成***************') % rel_type)
        return relations_list
if __name__ == '__main__':
    list=[]
    with open("../data/cve/nvdcve-1.1-2019.json", encoding='utf-8') as f:
        dict1 = json.load(f)
        list+=['cve_id:'+i['cve']['CVE_data_meta']['ID'] for i in dict1['CVE_Items']]
        f.close()
    with open("../data/cve/nvdcve-1.1-2020.json", encoding='utf-8') as f:
        dict1 = json.load(f)
        list+=['cve_id:'+i['cve']['CVE_data_meta']['ID'] for i in dict1['CVE_Items']]
        f.close()
    with open("../data/cve/nvdcve-1.1-2021.json", encoding='utf-8') as f:
        dict1 = json.load(f)
        list+=['cve_id:'+i['cve']['CVE_data_meta']['ID'] for i in dict1['CVE_Items']]
        f.close()
    with open("../data/cve/nvdcve-1.1-2022.json", encoding='utf-8') as f:
        dict1 = json.load(f)
        list+=['cve_id:'+i['cve']['CVE_data_meta']['ID'] for i in dict1['CVE_Items']]
        f.close()
    with open('data_for_test_acc.txt','w', encoding='utf-8') as f:
        for i in list:
            f.writelines(i+'\n')
        f.close()
     # handler=SecurityGraph()
     # alllist=handler.read_com5g()
     # print('***************创建节点列表中***************')
     # nodedict,allnodelist=handler.create_com5g_nodeslist(alllist)
     # print('***************创建关系列表中***************')
     # allralationlist=handler.create_relationship_com5g_list(alllist,nodedict)
     # print('***************更新数据库***************')
     # handler.batch_create(allnodelist, allralationlist,1)
     # print('***************融合重复节点***************')
     # handler.merge_repeat_nodes()
     # print('***************更新索引***************')
     # handler.update_index()



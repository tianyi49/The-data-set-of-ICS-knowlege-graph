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
        self.data_path = os.path.join(cur_dir, 'data/cve/nvdcve-1.1-2022.json')
        self.g = Graph(
            host="127.0.0.1",  # neo4j 搭载服务器的ip地址，ifconfig可获取到
            http_port=7474,  # neo4j 服务器监听的端口号
            user="neo4j",  # 数据库user name，如果没有更改过，应该是neo4j
            password="123456")

    '''找到"cve configurations"中的cpestr'''
    def find_cpestr(self,nodes,cvevendor,cveproduct, cveproductversion,rels_product_productversion,rels_product_vendor, rels_product_producttype,rels_product,cveidinstance,cveinstanceinfo):
        for node in nodes:
            if(node["operator"]=='OR'):
                for cpematch in node["cpe_match"]:
                    cpestr=cpematch["cpe23Uri"]
                    cpestr= re.search(r'((?<=cpe:2.3:).):(.*?):(.*?):(.*?):', cpestr, re.M | re.I)
                    producttypepart= cpestr.group(1)
                    cvevendor.append(cpestr.group(2))
                    cveproduct.append(cpestr.group(3))
                    cveproductversion.append(cpestr.group(3)+':'+cpestr.group(4))
                    rels_product_vendor.append([cpestr.group(3),cpestr.group(2)])
                    rels_product.append([cveidinstance,cpestr.group(3)])
                    rels_product_productversion.append([cpestr.group(3),cpestr.group(3)+':'+cpestr.group(4)])
                    if producttypepart == 'a':
                        rels_product_producttype.append([cpestr.group(3),'software'])
                        cveinstanceinfo["cvetypevendorproduct"].append(['software',cpestr.group(2),cpestr.group(3)+':'+cpestr.group(4)])
                    elif producttypepart== 'h':
                        rels_product_producttype.append([cpestr.group(3), 'hardware'])
                        cveinstanceinfo["cvetypevendorproduct"].append(['hardware', cpestr.group(2), cpestr.group(3)+':'+cpestr.group(4)])
                    elif producttypepart == 'o':
                        rels_product_producttype.append([cpestr.group(3), 'operatingsystem'])
                        cveinstanceinfo["cvetypevendorproduct"].append(['operatingsystem', cpestr.group(2), cpestr.group(3)+':'+cpestr.group(4)])
                    else:
                        pass
            elif(node["operator"]=='AND'):
                self.find_cpestr(node["children"],cvevendor,cveproduct, cveproductversion,rels_product_productversion,rels_product_vendor, rels_product_producttype,rels_product,cveidinstance,cveinstanceinfo)

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
    '''读取cve文件'''
    def read_nodescve(self):
        # 构建实体节点
        cveinfo={}  #整理后的信息
        cveid = []  # 唯一性的约束ID,元素成员[cveid,cvedescription]
        cveproduct= []  # cve产品
        cveproductversion=[]  #cve产品带版本
        cvevendor = []  # cve厂商
        producttype= ['software','hardware','operatingsystem']  # 产品类别
        cvssversin=[]  #cvss版本
        attackvector = [] #攻击向量
        attackComplexity = []  # 攻击复杂度
        privilegesRequired=[]  #权限要求
        userInteraction=[]
        confidentialityImpact=[]
        integrityImpact=[]
        availabilityImpact=[]
        cvssbaseScore=[]
        baseSeverity=[]
        exploitabilityScore=[]
        impactScore=[]
        publishedDate=[]
        cveversion=[]
        cveScope=['Confidentiality','Integrity','Availability','Severity']
        # 构建节点实体关系默认为与cveid的关系
        rels_product = []
        rels_product_vendor = []
        rels_product_producttype = []
        rels_product_productversion=[]
        rels_cvssversin= []  #其它指标与cvssversion的关系
        rels_cwe=[]
        #以下cvss评分项目v3和v2通用
        rels_attackvector  = []
        rels_attackComplexity=[]
        rels_privilegesRequired= []
        rels_userInteraction= []
        rels_confidentialityImpact = []
        rels_integrityImpact= []
        rels_availabilityImpact = []
        rels_cvssbaseScore = []
        rels_baseSeverity = []
        rels_exploitabilityScore=[]
        rels_impactScore= []
        rels_publishedDate = []
        rels_cveversion=[]
        rels_impact_scope=[]
        counttotal = 0

        for  yearnum in range(2,24,1):
            if(yearnum<10):
                yearnumstr='0'+str(yearnum)
            else:
                yearnumstr = str(yearnum)
            count = 0
            with open("data/cve/nvdcve-1.1-20" + yearnumstr + ".json", encoding='utf-8') as f:
                dict1 = json.load(f)
                for cveitem in dict1["CVE_Items"]:
                    cveinstanceinfo={"cveid":'',"cvedescription":'',"cvetypevendorproduct":[],"cveralatecwe":[],"cvssversion":'',"attackVector":'',"attackComplexity":'',
                                     "privilegesRequired":'',"userInteraction":'',"integrityImpact":'',"confidentialityImpact":'',"availabilityImpact":'',"baseScore":'',
                                    "baseSeverity":'',"exploitabilityScore":'',"impactScore":'',"publishedDate":''}
                    count+=1#漏洞数量计算
                    # 添加漏洞基本信息元素成员为[cveid:,descripyion:]
                    cveidinstance=cveitem["cve"]["CVE_data_meta"]["ID"]
                    cveinstanceinfo["cveid"]= cveidinstance
                    cveinstanceinfo["cvedescription"]=cveitem["cve"]["description"]["description_data"][0]["value"]
                    cveid.append([cveidinstance,cveitem["cve"]["description"]["description_data"][0]["value"]])
                    #添加cve数据版本
                    cveversion.append(cveitem["cve"]["data_version"])
                    rels_cveversion.append(([cveidinstance,cveitem["cve"]["data_version"]]))
                    cveinstanceinfo["data_version"]=cveitem["cve"]["data_version"]
                    #添加产品、厂商、产品类型
                    cpestrlist=cveitem["configurations"]["nodes"]
                    self.find_cpestr(cpestrlist,cvevendor,cveproduct,cveproductversion,rels_product_productversion,rels_product_vendor,rels_product_producttype,rels_product,cveidinstance,cveinstanceinfo)
                    #添加相关cwe
                    try:
                        for cverelatecweinstance in cveitem["cve"]["problemtype"]["problemtype_data"][0]["description"]:
                            if (cverelatecweinstance["value"][0] == 'C'):
                                rels_cwe.append([cveidinstance,cverelatecweinstance["value"]])
                                cveinstanceinfo["cveralatecwe"].append(cverelatecweinstance["value"])
                    except:
                        pass
                    #cvss信息v3版本
                    if("baseMetricV3" in cveitem["impact"]):
                        try:
                            cvssversininstance=cveitem["impact"]["baseMetricV3"]["cvssV3"]["version"]
                            cvssversin.append(cvssversininstance)
                            cveinstanceinfo['cvssversion']=cvssversininstance
                            try:
                                attackvector.append(cveitem["impact"]["baseMetricV3"]["cvssV3"]["attackVector"])
                                attackComplexity.append(cveitem["impact"]["baseMetricV3"]["cvssV3"]["attackComplexity"])
                                privilegesRequired.append(cveitem["impact"]["baseMetricV3"]["cvssV3"]["privilegesRequired"])
                                userInteraction.append(cveitem["impact"]["baseMetricV3"]["cvssV3"]["userInteraction"])
                                integrityImpact.append(cveitem["impact"]["baseMetricV3"]["cvssV3"]["integrityImpact"])
                                confidentialityImpact.append(cveitem["impact"]["baseMetricV3"]["cvssV3"]["confidentialityImpact"])
                                availabilityImpact.append(cveitem["impact"]["baseMetricV3"]["cvssV3"]["availabilityImpact"])
                                cvssbaseScore.append(cveitem["impact"]["baseMetricV3"]["cvssV3"]["baseScore"])
                                baseSeverity.append(cveitem["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"])
                                exploitabilityScore.append(cveitem["impact"]["baseMetricV3"]["exploitabilityScore"])
                                impactScore.append(cveitem["impact"]["baseMetricV3"]["impactScore"])
                                rels_impact_scope.append([cveitem["impact"]["baseMetricV3"]["cvssV3"]["confidentialityImpact"], cveScope[0]])
                                rels_impact_scope.append([cveitem["impact"]["baseMetricV3"]["cvssV3"]["integrityImpact"], cveScope[1]])
                                rels_impact_scope.append([cveitem["impact"]["baseMetricV3"]["cvssV3"]["availabilityImpact"], cveScope[2]])
                                rels_impact_scope.append([cveitem["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"], cveScope[3]])
                                cveinstanceinfo['attackVector']=cveitem["impact"]["baseMetricV3"]["cvssV3"]["attackVector"]
                                cveinstanceinfo['attackComplexity']=cveitem["impact"]["baseMetricV3"]["cvssV3"]["attackComplexity"]
                                cveinstanceinfo['privilegesRequired']=cveitem["impact"]["baseMetricV3"]["cvssV3"]["privilegesRequired"]
                                cveinstanceinfo['userInteraction'] =cveitem["impact"]["baseMetricV3"]["cvssV3"]["userInteraction"]
                                cveinstanceinfo['integrityImpact'] =cveitem["impact"]["baseMetricV3"]["cvssV3"]["integrityImpact"]
                                cveinstanceinfo['confidentialityImpact'] =cveitem["impact"]["baseMetricV3"]["cvssV3"]["confidentialityImpact"]
                                cveinstanceinfo['availabilityImpact'] =cveitem["impact"]["baseMetricV3"]["cvssV3"]["availabilityImpact"]
                                cveinstanceinfo['baseScore'] =cveitem["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
                                cveinstanceinfo['baseSeverity'] =cveitem["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
                                cveinstanceinfo['exploitabilityScore'] =cveitem["impact"]["baseMetricV3"]["exploitabilityScore"]
                                cveinstanceinfo['impactScore'] =cveitem["impact"]["baseMetricV3"]["impactScore"]
                            except:
                                print('cvss信息V3'+cveidinstance)
                                pass
                            try:
                                rels_attackvector.append(
                                    [cveidinstance, cveitem["impact"]["baseMetricV3"]["cvssV3"]["attackVector"]])
                                rels_cvssversin.append([cveitem["impact"]["baseMetricV3"]["cvssV3"]["attackVector"], cvssversininstance])
                            except:
                                pass
                            try:
                                rels_attackComplexity.append([cveidinstance,cveitem["impact"]["baseMetricV3"]["cvssV3"]["attackComplexity"]])
                                rels_privilegesRequired.append([cveidinstance,cveitem["impact"]["baseMetricV3"]["cvssV3"]["privilegesRequired"]])
                                rels_cvssversin.append([cveitem["impact"]["baseMetricV3"]["cvssV3"]["attackComplexity"],  cvssversininstance])
                                rels_cvssversin.append([cveitem["impact"]["baseMetricV3"]["cvssV3"]["privilegesRequired"],  cvssversininstance])
                            except:
                                pass
                            try:
                                rels_userInteraction.append([cveidinstance,cveitem["impact"]["baseMetricV3"]["cvssV3"]["userInteraction"]])
                                rels_integrityImpact.append([cveidinstance,cveitem["impact"]["baseMetricV3"]["cvssV3"]["integrityImpact"]])
                                rels_cvssversin.append([cveitem["impact"]["baseMetricV3"]["cvssV3"]["userInteraction"],  cvssversininstance])
                                rels_cvssversin.append([cveitem["impact"]["baseMetricV3"]["cvssV3"]["integrityImpact"],  cvssversininstance])
                            except:
                                pass
                            try:
                                rels_confidentialityImpact.append([cveidinstance,cveitem["impact"]["baseMetricV3"]["cvssV3"]["confidentialityImpact"]])
                                rels_availabilityImpact.append([cveidinstance,cveitem["impact"]["baseMetricV3"]["cvssV3"]["availabilityImpact"]])
                                rels_cvssversin.append([cveitem["impact"]["baseMetricV3"]["cvssV3"]["confidentialityImpact"],  cvssversininstance])
                                rels_cvssversin.append([cveitem["impact"]["baseMetricV3"]["cvssV3"]["availabilityImpact"],  cvssversininstance])
                            except:
                                pass
                            try:
                                rels_cvssbaseScore.append([cveidinstance, cveitem["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]])
                                rels_baseSeverity.append([cveidinstance, cveitem["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]])
                                rels_cvssversin.append([cveitem["impact"]["baseMetricV3"]["cvssV3"]["baseScore"],  cvssversininstance])
                                rels_cvssversin.append([cveitem["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"],  cvssversininstance])
                            except:
                                pass
                            try:
                                rels_exploitabilityScore.append([cveidinstance, cveitem["impact"]["baseMetricV3"]["exploitabilityScore"]])
                                rels_impactScore.append([cveidinstance, cveitem["impact"]["baseMetricV3"]["impactScore"]])
                                rels_cvssversin.append([cveitem["impact"]["baseMetricV3"]["exploitabilityScore"],  cvssversininstance])
                                rels_cvssversin.append([cveitem["impact"]["baseMetricV3"]["impactScore"],  cvssversininstance])
                            except:
                                pass
                        except:
                            pass
                    # cvss信息v2版本
                    elif("baseMetricV2" in cveitem["impact"]):
                        try:
                            cvssversininstance = cveitem["impact"]["baseMetricV2"]["cvssV2"]["version"]
                            cvssversin.append(cvssversininstance)
                            cveinstanceinfo['cvssversion']=cvssversininstance
                            try:
                                attackvector.append(cveitem["impact"]["baseMetricV2"]["cvssV2"]["accessVector"])
                                rels_attackvector.append(
                                    [cveidinstance, cveitem["impact"]["baseMetricV2"]["cvssV2"]["accessVector"]])
                                rels_cvssversin.append(
                                    [cveitem["impact"]["baseMetricV2"]["cvssV2"]["accessVector"], cvssversininstance])
                                cveinstanceinfo['attackVector'] = cveitem["impact"]["baseMetricV2"]["cvssV2"]["accessVector"]
                            except:
                                pass
                            try:
                                attackComplexity.append(cveitem["impact"]["baseMetricV2"]["cvssV2"]["accessComplexity"])
                                rels_attackComplexity.append(
                                    [cveidinstance, cveitem["impact"]["baseMetricV2"]["cvssV2"]["accessComplexity"]])
                                rels_cvssversin.append([cveitem["impact"]["baseMetricV2"]["cvssV2"]["accessComplexity"],
                                                        cvssversininstance])
                                cveinstanceinfo['attackComplexity']=cveitem["impact"]["baseMetricV2"]["cvssV2"]["accessComplexity"]
                            except:
                                pass
                            try:
                                privilegesRequired.append(
                                    cveitem["impact"]["baseMetricV2"]["cvssV2"]["authentication"])
                                rels_privilegesRequired.append(
                                    [cveidinstance, cveitem["impact"]["baseMetricV2"]["cvssV2"]["authentication"]])
                                rels_cvssversin.append(
                                    [cveitem["impact"]["baseMetricV2"]["cvssV2"]["authentication"],
                                     cvssversininstance])
                                cveinstanceinfo['privilegesRequired']=cveitem["impact"]["baseMetricV2"]["cvssV2"]["authentication"]
                            except:
                                pass
                            try:
                                userInteractioninstance=cveitem["impact"]["baseMetricV2"]["userInteractionRequired"]
                                #程度说明词统一
                                if(userInteractioninstance==1):
                                    userInteractioninstance='REQUIRED'
                                elif(userInteractioninstance==0):
                                    userInteractioninstance = 'NONE'
                                userInteraction.append(userInteractioninstance)
                                rels_cvssversin.append([userInteractioninstance,cvssversininstance])
                                rels_userInteraction.append([cveidinstance, userInteractioninstance])
                                cveinstanceinfo['userInteraction'] =userInteractioninstance
                            except:
                                pass
                            try:
                                integrityImpact.append(cveitem["impact"]["baseMetricV2"]["cvssV2"]["integrityImpact"])
                                rels_integrityImpact.append([cveidinstance, cveitem["impact"]["baseMetricV2"]["cvssV2"]["integrityImpact"]])
                                rels_cvssversin.append([cveitem["impact"]["baseMetricV2"]["cvssV2"]["integrityImpact"],
                                                        cvssversininstance])
                                cveinstanceinfo['integrityImpact'] =cveitem["impact"]["baseMetricV2"]["cvssV2"]["integrityImpact"]
                                rels_impact_scope.append([cveitem["impact"]["baseMetricV2"]["cvssV2"]["integrityImpact"], cveScope[1]])
                            except:
                                pass
                            try:
                                confidentialityImpact.append(cveitem["impact"]["baseMetricV2"]["cvssV2"]["confidentialityImpact"])
                                rels_confidentialityImpact.append([cveidinstance,cveitem["impact"]["baseMetricV2"]["cvssV2"]["confidentialityImpact"]])
                                rels_cvssversin.append(
                                    [cveitem["impact"]["baseMetricV2"]["cvssV2"]["confidentialityImpact"],
                                     cvssversininstance])
                                cveinstanceinfo['confidentialityImpact'] =cveitem["impact"]["baseMetricV2"]["cvssV2"]["confidentialityImpact"]
                                rels_impact_scope.append([cveitem["impact"]["baseMetricV2"]["cvssV2"]["confidentialityImpact"], cveScope[0]])
                            except:
                                pass
                            try:
                                availabilityImpact.append(
                                    cveitem["impact"]["baseMetricV2"]["cvssV2"]["availabilityImpact"])
                                rels_availabilityImpact.append(
                                    [cveidinstance, cveitem["impact"]["baseMetricV2"]["cvssV2"]["availabilityImpact"]])
                                rels_cvssversin.append(
                                    [cveitem["impact"]["baseMetricV2"]["cvssV2"]["availabilityImpact"],
                                     cvssversininstance])
                                cveinstanceinfo['availabilityImpact'] =cveitem["impact"]["baseMetricV2"]["cvssV2"]["availabilityImpact"]
                                rels_impact_scope.append([cveitem["impact"]["baseMetricV2"]["cvssV2"]["availabilityImpact"], cveScope[2]])
                            except:
                                pass
                            try:
                                cvssbaseScore.append(cveitem["impact"]["baseMetricV2"]["cvssV2"]["baseScore"])
                                rels_cvssbaseScore.append([cveidinstance, cveitem["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]])
                                rels_cvssversin.append([cveitem["impact"]["baseMetricV2"]["cvssV2"]["baseScore"], cvssversininstance])
                                cveinstanceinfo['baseScore'] =cveitem["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
                            except:
                                pass
                            try:
                                baseSeverity.append(cveitem["impact"]["baseMetricV2"]["severity"])
                                rels_baseSeverity.append([cveidinstance, cveitem["impact"]["baseMetricV2"]["severity"]])
                                rels_cvssversin.append([cveitem["impact"]["baseMetricV2"]["severity"], cvssversininstance])
                                cveinstanceinfo['baseSeverity'] =cveitem["impact"]["baseMetricV2"]["severity"]
                                rels_impact_scope.append([cveitem["impact"]["baseMetricV2"]["severity"], cveScope[3]])
                            except:
                                pass
                            try:
                                exploitabilityScore.append(cveitem["impact"]["baseMetricV2"]["exploitabilityScore"])
                                rels_exploitabilityScore.append(
                                    [cveidinstance, cveitem["impact"]["baseMetricV2"]["exploitabilityScore"]])
                                rels_cvssversin.append(
                                    [cveitem["impact"]["baseMetricV2"]["exploitabilityScore"], cvssversininstance])
                                cveinstanceinfo['exploitabilityScore'] =cveitem["impact"]["baseMetricV2"]["exploitabilityScore"]
                            except:
                                pass
                            try:
                                impactScore.append(cveitem["impact"]["baseMetricV2"]["impactScore"])
                                rels_impactScore.append(
                                    [cveidinstance, cveitem["impact"]["baseMetricV2"]["impactScore"]])
                                rels_cvssversin.append(
                                    [cveitem["impact"]["baseMetricV2"]["impactScore"], cvssversininstance])
                                cveinstanceinfo['impactScore'] =cveitem["impact"]["baseMetricV2"]["impactScore"]
                            except:
                                pass
                        except:
                            pass
                    try:
                        publishedDatepart=cveitem["publishedDate"].split('T')[0]
                    except:
                        publishedDatepart=cveidinstance.split('-',2)[1]
                    publishedDate.append(publishedDatepart)
                    rels_publishedDate.append([cveidinstance,publishedDatepart])
                    cveinstanceinfo['publishedDate'] =publishedDatepart
                    cveinfo["%d"%(counttotal+count)]=cveinstanceinfo
                counttotal+=count
                print("data/cve/nvdcve-1.1-20" + yearnumstr+"共有多少个cve节点：%d"%count)
            f.close()
        with open("cveinfo.json","w",encoding='utf-8') as f:
            json.dump(cveinfo,f,indent=4)
            f.close
        print("总共有%d条漏洞"%counttotal)
        NodeRelationlist[0]=[self.setList(cveid),set(cveproduct),set(cveproductversion),set(cvevendor),set(producttype),
                             set(cvssversin),set(attackvector),set(attackComplexity),set(privilegesRequired),set(userInteraction),
                             set(confidentialityImpact),set(integrityImpact),set(availabilityImpact),set(cvssbaseScore),
                             set(baseSeverity),set(exploitabilityScore),set(impactScore),set(publishedDate),set(cveversion),set(cveScope)]

        NodeRelationlist[1]=[self.setList(rels_product),self.setList(rels_product_vendor),self.setList(rels_product_producttype),
                             self.setList(rels_product_productversion),self.setList(rels_cvssversin),self.setList(rels_cwe),
                             self.setList(rels_attackvector),self.setList(rels_attackComplexity),self.setList( rels_privilegesRequired),
                             self.setList(rels_userInteraction),self.setList(rels_confidentialityImpact),self.setList(rels_integrityImpact),
                             self.setList(rels_availabilityImpact),self.setList(rels_cvssbaseScore),self.setList( rels_baseSeverity),
                             self.setList(rels_exploitabilityScore),self.setList(rels_impactScore),self.setList(rels_publishedDate),
                             self.setList(rels_cveversion),self.setList(rels_impact_scope)]
        return NodeRelationlist
    '''读取cwe文件'''
    def read_nodescwe(self):

        cweinfo={}  #整理后的信息
        cweid = []  # 唯一性的约束ID,元素成员为[cweid:,cwetitle:,Abstraction:,cwedescription, cweExtendDescription]
        #cwedescription cwe描述,Abstraction:cwe的抽象程度
        #cweExtendDescription=[]#CWE的额外描述
        cwescope=[]#影响范围
        cweimpact=[]    #影响
        cweimpactLikelihood=[]
        cweimpactnote=[]#影响说明
        cweversion=[]#数据版本
        cwelikelihood=[] #利用的可能性
        cwemitigation=[]#缓解措施
        cwemitigationphase=[]   #缓解措施阶段
        cwemitigationStrategy=[]  #缓解措施策略
        cwemitigationEffectiveness=[] #缓解措施效率
        cweDetectionMethods=[]  #检测技巧
        cweDetectionDescription=[]  #检测技巧描述
        cweDetectionEffectiveness=[]  #检测技巧的效率
        # 构建节点实体关系默认为与cweid的关系
        rels_cwe=[]   #格式[cweid,cwerelationtype,cweid]
        rels_likelihood = []
        rels_mitigation = []
        rels_mitigation_phase=[]
        rels_mitigation_Strategy=[]
        rels_mitigation_Effectiveness=[]
        rels_cve = []
        rels_capec=[]
        rels_DetectionMethods=[]
        rels_DetectionDescription=[]
        rels_DetectionEffectiveness=[]
        rels_impact=[]
        rels_impact_scope=[]
        rels_impact_note=[]
        rels_impact_Likelihood=[]
        rels_cweversion=[]
        counttotal = 0
        # 读取文件
        dom = xml.dom.minidom.parse('data/cwe/cwec_v4.9.xml')
        docroot=dom.documentElement
        Weaknesses= docroot.getElementsByTagName('Weakness')
        cweversion.append(docroot.getAttribute('Version'))
        for weakness in Weaknesses:
            cweinstanceinfo = {"cweid": '', "cweversion":'',"cwedescription": '',"cweExtendDescription":'' , "cweimpact": [],
                               "cwelikelihood": '', "cwemitigation": [], "cweDetectionMethods": [], "cwerelatecwe": [],
                               "cwerelatecve": [], "cwerelatecapec": []}
            cweinstanceinfo['cweversion']=docroot.getAttribute('Version')
            counttotal+=1
            #添加id，描述，和版本信息
            cweidinstance='CWE-'+weakness.getAttribute('ID')
            cweinstanceinfo['cweid']=cweidinstance
            cweinstanceinfo['cwedescription']=weakness.getElementsByTagName('Description')[0].firstChild.data
            # 添加额外描述
            try:
                cweExDesnode = weakness.getElementsByTagName('Extended_Description')[0]
                cweExDescriptionlist = [];
                cweExDesinstance = ''
                self.extract_xml_childtexts(cweExDesnode, cweExDescriptionlist)
                for cweExDescriptiontext in cweExDescriptionlist:
                    cweExDesinstance += cweExDescriptiontext
                cweinstanceinfo['cweExtendDescription'] = cweExDesinstance
            except:
                pass
            cweid.append([cweidinstance, weakness.getAttribute('Name'), weakness.getAttribute('Abstraction'),weakness.getElementsByTagName('Description')[0].firstChild.data,cweExDesinstance])
            rels_cweversion.append([cweidinstance,docroot.getAttribute('Version')])
            #添加影响信息
            cweconsequences=weakness.getElementsByTagName('Consequence')
            for cweconsequence in cweconsequences:
                cwescopeinstances=cweconsequence.getElementsByTagName('Scope')
                cweimapctinstances=cweconsequence.getElementsByTagName('Impact')
                cweimpactnoteinstances=cweconsequence.getElementsByTagName('Note')
                cweinfoimpactdict={'Impact':[],'Scope':[],'Note':[],'Likelihood':''}
                try:
                    cweimpactLikelihood.append(cweconsequence.getElementsByTagName('Likelihood')[0].firstChild.data)
                    cweinfoimpactdict['Likelihood']=cweconsequence.getElementsByTagName('Likelihood')[0].firstChild.data
                    for cweimpactinstance in cweimapctinstances:
                        rels_impact_Likelihood.append([cweimpactinstance.firstChild.data,cweconsequence.getElementsByTagName('Likelihood')[0].firstChild.data])
                except:
                    #print("cweimpactLikelihood出错,"+cweidinstance+","+'%d'%counttotal)
                    pass
                for cweimpactinstance in cweimapctinstances:
                    cweimpact.append(cweimpactinstance.firstChild.data)
                    rels_impact.append([cweidinstance,cweimpactinstance.firstChild.data])
                    cweinfoimpactdict['Impact'].append(cweimpactinstance.firstChild.data)
                    for cwescopeinstance in cwescopeinstances:
                        rels_impact_scope.append([cweimpactinstance.firstChild.data,cwescopeinstance.firstChild.data])
                for cwescopeinstance in cwescopeinstances:
                    cwescope.append(cwescopeinstance.firstChild.data)
                    cweinfoimpactdict['Scope'].append(cwescopeinstance.firstChild.data)
                for cweimpactnoteinstance in cweimpactnoteinstances:
                    cweimpactnote.append(cweimpactnoteinstance.firstChild.data)
                    cweinfoimpactdict['Note'].append(cweimpactnoteinstance.firstChild.data)
                    for cweimpactinstance in cweimapctinstances:
                        rels_impact_note.append([cweimpactinstance.firstChild.data,cweimpactnoteinstance])
                cweinstanceinfo['cweimpact'].append(cweinfoimpactdict)
            #利用可能性
            try:
                cwelikelihood.append(weakness.getElementsByTagName('Likelihood_Of_Exploit')[0].firstChild.data)
                rels_likelihood.append([cweidinstance,weakness.getElementsByTagName('Likelihood_Of_Exploit')[0].firstChild.data])
                cweinstanceinfo["cwelikelihood"]=weakness.getElementsByTagName('Likelihood_Of_Exploit')[0].firstChild.data
            except:
                #print("Likelihood_Of_Exploit出错," + cweidinstance + ","+'%d'%counttotal)
                pass
            #缓解措施
            try:
                Mitigations=weakness.getElementsByTagName('Mitigation')
                for Mitigation in Mitigations:
                    try:
                        cweMitInfoDict={'Phase':'','Description':'','Effectiveness':'','Strategy':'',}
                        MitDescription=Mitigation.getElementsByTagName('Description')
                        #提取每个Mitigation 里面的Description所有文本
                        MitDescriptionlist=[];cwemitigationinstance=''
                        self.extract_xml_childtexts(MitDescription[0],MitDescriptionlist)
                        for MitDescriptiontext in MitDescriptionlist:
                            cwemitigationinstance+=MitDescriptiontext
                        cwemitigation.append(cwemitigationinstance)
                        rels_mitigation.append([cweidinstance,cwemitigationinstance])
                        cweMitInfoDict['Description']=cwemitigationinstance
                        try:
                            rels_mitigation_phase.append([cwemitigationinstance,Mitigation.getElementsByTagName('Phase')[0].firstChild.data])
                            cwemitigationphase.append(Mitigation.getElementsByTagName('Phase')[0].firstChild.data)
                            cweMitInfoDict['Phase'] =Mitigation.getElementsByTagName('Phase')[0].firstChild.data
                        except:
                           # print("cwemitigationphase出错," + cweidinstance + ","+'%d'%counttotal)
                            pass
                        try:
                            rels_mitigation_Effectiveness.append([cwemitigationinstance,Mitigation.getElementsByTagName('Effectiveness')[0].firstChild.data])
                            cwemitigationEffectiveness.append(Mitigation.getElementsByTagName('Effectiveness')[0].firstChild.data)
                            cweMitInfoDict['Effectiveness'] = Mitigation.getElementsByTagName('Effectiveness')[0].firstChild.data
                        except:
                            #print("cwemitigationEffectiveness出错," + cweidinstance + ","+'%d'%counttotal)
                            pass
                        try:
                            rels_mitigation_Strategy.append([cwemitigationinstance,Mitigation.getElementsByTagName('Strategy')[0].firstChild.data])
                            cwemitigationStrategy.append(Mitigation.getElementsByTagName('Strategy')[0].firstChild.data)
                            cweMitInfoDict['Strategy'] = Mitigation.getElementsByTagName('Strategy')[0].firstChild.data
                        except:
                            #print("cwemitigationStrategy出错," + cweidinstance + ","+'%d'%counttotal)
                            pass
                    except:
                        print("cwemitigation出错," + cweidinstance + ","+'%d'%counttotal)
                        pass
                    cweinstanceinfo['cwemitigation'].append(cweMitInfoDict)
            except:
                print("Mitigations出错," + cweidinstance + ","+'%d'%counttotal)
                pass
            #相关cwe
            try:
                cwerelateidinstances=weakness.getElementsByTagName('Related_Weakness')
                for cwerelateidinstance in cwerelateidinstances:
                    rels_cwe.append([cweidinstance,cwerelateidinstance.getAttribute('Nature'),'CWE'+cwerelateidinstance.getAttribute('CWE_ID')])
                    cweinstanceinfo['cwerelatecwe'].append([cwerelateidinstance.getAttribute('Nature'),'CWE-'+cwerelateidinstance.getAttribute('CWE_ID')])
            except:
                pass
            #检测技巧相关
            try:
                DetectionMethods=weakness.getElementsByTagName('Detection_Method')
                for DetectionMethod in DetectionMethods:
                    try:
                        cweDetInfoDict={'Method':'','Description':'','Effectiveness':''}
                        DetectionMethodinstance=DetectionMethod.getElementsByTagName('Method')[0].firstChild.data
                        cweDetectionMethods.append(DetectionMethodinstance)
                        rels_DetectionMethods.append([cweidinstance,DetectionMethodinstance])
                        cweDetInfoDict['Method']=DetectionMethodinstance
                        try:
                            DetectionDescriptionlist=[];cweDetectDescripInstance='';DetectionDescriptionnode=DetectionMethod.getElementsByTagName('Description')[0]
                            self.extract_xml_childtexts(DetectionDescriptionnode,DetectionDescriptionlist)
                            for DetectionDescriptiontext in DetectionDescriptionlist:
                                cweDetectDescripInstance+= DetectionDescriptiontext
                            cweDetectionDescription.append(cweDetectDescripInstance)
                            rels_DetectionDescription.append([DetectionMethodinstance,cweDetectDescripInstance])
                            cweDetInfoDict['Description'] =cweDetectDescripInstance
                        except:
                            pass
                        try:
                            cweDetectionEffectiveness.append(DetectionMethod.getElementsByTagName('Effectiveness')[0].firstChild.data)
                            rels_DetectionEffectiveness.append([DetectionMethodinstance,DetectionMethod.getElementsByTagName('Effectiveness')[0].firstChild.data])
                            cweDetInfoDict['Effectiveness'] =DetectionMethod.getElementsByTagName('Effectiveness')[0].firstChild.data
                        except:
                            pass
                    except:
                        pass
                    cweinstanceinfo['cweDetectionMethods'].append(cweDetInfoDict)
            except:
                pass
            #相关cve
            try:
                RelateCveList=weakness.getElementsByTagName('Observed_Example')
                for RelateCve in RelateCveList:
                    try:
                        RelateCveIns=RelateCve.getElementsByTagName('Reference')[0].firstChild.data
                        rels_cve.append([cweidinstance,RelateCveIns])
                        cweinstanceinfo['cwerelatecve'].append(RelateCveIns)
                    except:
                        pass
            except:
                pass
            #相关capec
            try:
                RelateCapecList = weakness.getElementsByTagName('Related_Attack_Pattern')
                for RelateCapec in RelateCapecList:
                    try:
                        RelateCapecIns = 'CAPEC-'+RelateCapec.getAttribute('CAPEC_ID')
                        rels_capec.append([cweidinstance,RelateCapecIns])
                        cweinstanceinfo['cwerelatecapec'].append(RelateCapecIns)
                    except:
                        pass
            except:
                pass
            cweinfo[cweidinstance]=cweinstanceinfo
        with open("cweinfo.json","w",encoding='utf-8') as f:
            json.dump(cweinfo,f,indent=4)
            f.close
        print("总共有%d条弱点"%counttotal)
        NodeRelationlist[0] =[self.setList(cweid),set(cwescope),set( cweimpact),set( cweimpactLikelihood),set( cweimpactnote),
                              set( cweversion),set( cwelikelihood),set( cwemitigation),set( cwemitigationphase),
                              set( cwemitigationStrategy),set( cwemitigationEffectiveness),set( cweDetectionMethods),
                              set( cweDetectionDescription),set( cweDetectionEffectiveness)]
        NodeRelationlist[1]=[self.setList(rels_cwe), self.setList(rels_likelihood), self.setList(rels_mitigation),
                             self.setList(rels_mitigation_phase), self.setList(rels_mitigation_Strategy),
                             self.setList(rels_mitigation_Effectiveness), self.setList(rels_cve), self.setList(rels_capec),
                             self.setList(rels_DetectionMethods), self.setList(rels_DetectionDescription),
                             self.setList(rels_DetectionEffectiveness), self.setList(rels_impact), self.setList(rels_impact_scope),
                             self.setList(rels_impact_note), self.setList(rels_impact_Likelihood), self.setList(rels_cweversion)]
        return NodeRelationlist
    def read_nodescapec(self):#ReturnFlag=0返回节点，ReturnFlag=1返回关系
        capecInfo = {}  # 整理后的信息
        capecID=[]  # 唯一性的约束ID,元素成员为[capecid:,capecname:,Abstraction: capecDescription]
        capecVersion=[]  # 数据版本
        capecLikelihood = []  # 利用的可能性
        capecSeverity=[]   #攻击的严重性
        capecSeverityScope=['Severity']   #影响范围
        capecAttackStepDes=[]  # 攻击步骤描述格式[[AttackStepDes,step1]]
        capecAttackPhase = []  #攻击阶段
        capecAttackTechnique=[]#攻击技术
        capecPrerequisites=[] #攻击条件
        capecSkillsRequired=[]#攻击技能要求[ Des,Level]
        capecResourcesRequired=[] #攻击源要求
        capecScope = []  # 后果范围
        capecImpact = []  # 影响
        capecImpactnote = []  # 影响说明
        capecMitigation = []  # 缓解措施
        # 构建节点实体关系默认为与capecID的关系
        rels_capec = []  # 格式[capecid,capecrelationtype,capecid]
        rels_capecVersion = []
        rels_Likelihood = []
        rels_Severity=[]
        rels_AttStepDes = []
        rels_AttStepDes_Phase= []
        rels_AttStepDes_Technique = []
        rels_Prerequisites=[]
        rels_SkillsRequired=[]
        rels_ResourcesRequired=[]
        rels_Impact=[]
        rels_Impact_scope =[]
        rels_Impact_note =[]
        rels_Mitigation=[]
        rels_cwe=[]
        rels_Severity_Scope=[]
        counttotal = 0
        # 读取文件
        dom = xml.dom.minidom.parse('data/capec/capec_v3.8.xml')
        docroot = dom.documentElement
        AttackPatterns= docroot.getElementsByTagName('Attack_Pattern')
        capecVersion.append(docroot.getAttribute('Version'))
        for AttackPattern in AttackPatterns:
            capecInfoIns={"capecID": '', "capecVersion":'',"capecDescription": '',"capecLikelihood":'',"capecRelatecwe": [],
                               "capecSeverity": '', "capecAttackStep": [], "capecPrerequisites": [], "capecSkillsRequired": [],
                               "capecResourcesRequired": [], "capecImpact": [], "capecMitigation": [], "capecRelatecapec": []}
            counttotal += 1
            #添加id，描述，和版本信息
            capecIDIns = 'CAPEC-' + AttackPattern.getAttribute('ID')
            capecDescriptionIns=''
            try:
                capecDescriptionIns= AttackPattern.getElementsByTagName('Description')[0].firstChild.data
                capecInfoIns['capecDescription'] = AttackPattern.getElementsByTagName('Description')[0].firstChild.data
            except:
                print('CAPEC-'+AttackPattern.getAttribute('ID')+"capecDescriptionc错误")
            capecID.append([capecIDIns, AttackPattern.getAttribute('Name'), AttackPattern.getAttribute('Abstraction'),capecDescriptionIns])
            capecInfoIns['capecID'] = [capecIDIns, AttackPattern.getAttribute('Name'),AttackPattern.getAttribute('Abstraction')]
            rels_capecVersion.append([capecIDIns, docroot.getAttribute('Version')])
            capecInfoIns["capecVersion"] = docroot.getAttribute('Version')
            #添加利用可能性、严重性
            try:
                capecLikelihood.append(AttackPattern.getElementsByTagName('Likelihood_Of_Attack')[0].firstChild.data)
                rels_Likelihood.append([capecIDIns,AttackPattern.getElementsByTagName('Likelihood_Of_Attack')[0].firstChild.data])
                capecInfoIns['capecLikelihood'] =AttackPattern.getElementsByTagName('Likelihood_Of_Attack')[0].firstChild.data
            except:
                pass
            try:
                capecSeverity.append(AttackPattern.getElementsByTagName('Typical_Severity')[0].firstChild.data)
                rels_Severity.append([capecIDIns, AttackPattern.getElementsByTagName('Typical_Severity')[0].firstChild.data])
                rels_Severity_Scope.append([AttackPattern.getElementsByTagName('Typical_Severity')[0].firstChild.data,capecSeverity[0]])
                capecInfoIns['capecSeverity'] = AttackPattern.getElementsByTagName('Typical_Severity')[0].firstChild.data
            except:
                pass
            #添加相关capec
            try:
                RelatecapecList=AttackPattern.getElementsByTagName('Related_Attack_Pattern')
                for Relatecapec in RelatecapecList:
                    RelatecapecIns='CAPEC-'+Relatecapec.getAttribute('CAPEC_ID')
                    rels_capec.append([capecIDIns,Relatecapec.getAttribute('Nature'),RelatecapecIns])
                    capecInfoIns['capecRelatecapec'].append([Relatecapec.getAttribute('Nature'),RelatecapecIns])
            except:
                pass
            #添加capecAttackStep
            try:
                AttackStepList=AttackPattern.getElementsByTagName('Attack_Step')
                for AttackStep in AttackStepList:
                    AttackStepDict = {'step': '', 'Description': '', 'Phase': '', 'Technique': []}
                    AttackStepDesIns=AttackStep.getElementsByTagName('Description')[0].firstChild.data
                    capecAttackStepDes.append([AttackStepDesIns,AttackStep.getElementsByTagName('Step')[0].firstChild.data])
                    rels_AttStepDes.append([capecIDIns,AttackStepDesIns])
                    AttackStepDict['step']=AttackStep.getElementsByTagName('Step')[0].firstChild.data
                    AttackStepDict['Description'] =AttackStepDesIns
                    try:
                        capecAttackPhaseIns=AttackStep.getElementsByTagName('Phase')[0].firstChild.data
                        capecAttackPhase.append(capecAttackPhaseIns)
                        rels_AttStepDes_Phase.append([AttackStepDesIns,capecAttackPhaseIns])
                        AttackStepDict['Phase']=capecAttackPhaseIns
                    except:
                        pass
                    try:
                        capecAttTecList=AttackStep.getElementsByTagName('Technique')
                        for capecAttTec in capecAttTecList:
                            capecAttackTechnique.append(capecAttTec.firstChild.data)
                            rels_AttStepDes_Technique.append([AttackStepDesIns,capecAttTec.firstChild.data])
                            AttackStepDict["Technique"].append(capecAttTec.firstChild.data)
                    except:
                        pass
                    capecInfoIns['capecAttackStep'].append(AttackStepDict)
            except:
                pass
            #添加攻击条件
            try:
                PrerequisitesList=AttackPattern.getElementsByTagName('Prerequisite')
                for Prerequisites in PrerequisitesList:
                    capecPrerequisites.append(Prerequisites.firstChild.data)
                    capecInfoIns["capecPrerequisites"].append(Prerequisites.firstChild.data)
                    rels_Prerequisites.append([capecIDIns,Prerequisites.firstChild.data])
            except:
                pass
            #添加攻击技能要求
            try:
                SkillsRequiredList=AttackPattern.getElementsByTagName('Skill')
                for SkillsRequired in SkillsRequiredList:
                    capecSkillsRequired.append([SkillsRequired.firstChild.data,SkillsRequired.getAttribute('Level')])
                    capecInfoIns["capecSkillsRequired"].append([SkillsRequired.getAttribute('Level'),SkillsRequired.firstChild.data])
                    rels_SkillsRequired.append([capecIDIns,SkillsRequired.firstChild.data])
            except:
                pass
            #添加攻击源要求
            try:
                ResourcesRequiredList=AttackPattern.getElementsByTagName('Resource')
                for ResourcesRequired in ResourcesRequiredList:
                    capecResourcesRequired.append(ResourcesRequired.firstChild.data)
                    capecInfoIns["capecResourcesRequired"].append(ResourcesRequired.firstChild.data)
                    rels_ResourcesRequired.append([capecIDIns,ResourcesRequired.firstChild.data])
            except:
                pass
            #添加攻击影响
            try:
                capecconsequences = AttackPattern.getElementsByTagName('Consequence')
                for capecconsequence in capecconsequences:
                    capecscopeinstances = capecconsequence.getElementsByTagName('Scope')
                    capecimapctinstances = capecconsequence.getElementsByTagName('Impact')
                    try:
                        capecimpactnoteinstances = capecconsequence.getElementsByTagName('Note')
                        for capecimpactnoteinstance in capecimpactnoteinstances:
                            capecImpactnote.append(capecimpactnoteinstance.firstChild.data)
                            capecinfoimpactdict['Note'].append(capecimpactnoteinstance.firstChild.data)
                            for capecimpactinstance in capecimapctinstances:
                                rels_Impact_note.append([capecimpactinstance.firstChild.data, capecimpactnoteinstance])
                    except:
                        pass
                    capecinfoimpactdict = {'Impact': [], 'Scope': [], 'Note': []}
                    for capecimpactinstance in capecimapctinstances:
                        capecImpact.append(capecimpactinstance.firstChild.data)
                        rels_Impact.append([capecIDIns, capecimpactinstance.firstChild.data])
                        capecinfoimpactdict['Impact'].append(capecimpactinstance.firstChild.data)
                        for capecscopeinstance in capecscopeinstances:
                            rels_Impact_scope.append([capecimpactinstance.firstChild.data, capecscopeinstance.firstChild.data])
                    for capecscopeinstance in capecscopeinstances:
                        capecScope.append(capecscopeinstance.firstChild.data)
                        capecinfoimpactdict['Scope'].append(capecscopeinstance.firstChild.data)
                    capecInfoIns['capecImpact'].append(capecinfoimpactdict)
            except:
                pass
            #添加缓解措施
            try:
                Mitigations = AttackPattern.getElementsByTagName('Mitigation')
                for Mitigation in Mitigations:
                    try:
                        MitDescriptionlist = [];
                        capecmitigationinstance = ''
                        self.extract_xml_childtexts(Mitigation, MitDescriptionlist)
                        for MitDescriptiontext in MitDescriptionlist:
                            if(len(MitDescriptiontext)>0):
                                capecmitigationinstance += MitDescriptiontext
                        capecMitigation.append(capecmitigationinstance)
                        rels_Mitigation.append([capecIDIns, capecmitigationinstance])
                        capecInfoIns["capecMitigation"].append(capecmitigationinstance)
                    except:
                        print("Mitigations出错," + capecIDIns + "," + '%d' % counttotal)
                        pass
            except:
                print("Mitigations出错," + capecIDIns + ","+'%d'%counttotal)
                pass
            #添加相关cwe
            try:
                RelateCweList = AttackPattern.getElementsByTagName('Related_Weakness')
                for RelateCwe in RelateCweList:
                    try:
                        RelateCweIns = 'CWE-' + RelateCwe.getAttribute('CWE_ID')
                        rels_cwe.append([capecIDIns,RelateCweIns])
                        capecInfoIns['capecRelatecwe'].append(RelateCweIns)
                    except:
                        pass
            except:
                pass
            capecInfo[capecIDIns]=capecInfoIns
        with open("capecinfo.json","w",encoding='utf-8') as f:
            json.dump( capecInfo,f,indent=4)
            f.close
        print("总共有%d条攻击模式"%counttotal)
        NodeRelationlist[0]=[self.setList(capecID), set(capecVersion), set(capecLikelihood), set(capecSeverity),
                             capecSeverityScope,self.setList(capecAttackStepDes), set(capecAttackPhase), set(capecAttackTechnique),
                             set(capecPrerequisites),self.setList(capecSkillsRequired), set(capecResourcesRequired),
                             set(capecScope ), set(capecImpact ), set(capecImpactnote)]
        NodeRelationlist[1]=[self.setList(rels_capec) ,self.setList(rels_capecVersion) ,self.setList( rels_Likelihood),
                             self.setList( rels_Severity),self.setList( rels_AttStepDes ),self.setList( rels_AttStepDes_Phase ),
                             self.setList(rels_AttStepDes_Technique  ),self.setList( rels_Prerequisites),self.setList( rels_SkillsRequired),
                             self.setList( rels_ResourcesRequired),self.setList( rels_Impact),self.setList( rels_Impact_scope ),
                             self.setList(rels_Impact_note ),self.setList( rels_Mitigation),self.setList( rels_cwe),self.setList(rels_Severity_Scope)]
        return NodeRelationlist
    def create_nodes_relationships(self):
        allnodelist=[];allrelationlist=[]
        # cve节点读取
        cvenodelist=self.read_nodescve()[0]
        cverelationlist=self.read_nodescve()[1]
        allnodelist.append(cvenodelist);allrelationlist.append(cverelationlist)
        # cveid, cveproduct, cveproductversion, cvevendor, cveproducttype, cvssversin, \
        # cveattackvector, cveattackComplexity, cveprivilegesRequired, userInteraction, confidentialityImpact, integrityImpact, \
        # availabilityImpact, cvssbaseScore, baseSeverity, exploitabilityScore, impactScore, \
        # publishedDate, cveversion, cveScope = self.read_nodescve()[0]
        # cve_rels_product, cve_rels_product_vendor, cve_rels_product_producttype, cve_rels_product_productversion, cve_rels_cvssversin, \
        # cve_rels_cwe, cve_rels_attackvector, cve_rels_attackComplexity, cve_rels_privilegesRequired, cve_rels_userInteraction, \
        # cve_rels_confidentialityImpact, cve_rels_integrityImpact, cve_rels_availabilityImpact, cve_rels_cvssbaseScore, cve_rels_baseSeverity, \
        # cve_rels_exploitabilityScore, cve_rels_impactScore, cve_rels_publishedDate, cve_rels_cveversion, cve_rels_impact_scope =self.read_nodescve()[1]
        #cwe节点读取
        cwenodelist=self.read_nodescwe()[0]
        cwerelationlist=self.read_nodescwe()[1]
        allnodelist.append(cwenodelist);allrelationlist.append(cwerelationlist)
        # cweid,cwescope,cweimpact, \
        # cweimpactLikelihood,cweimpactnote,cweversion,cwelikelihood,cwemitigation, \
        # cwemitigationphase,cwemitigationStrategy,cwemitigationEffectiveness,cweDetectionMethods, \
        # cweDetectionDescription,cweDetectionEffectiveness=cwenodelist
        # cwe_rels_cwe, cwe_rels_likelihood, cwe_rels_mitigation, cwe_rels_mitigation_phase, cwe_rels_mitigation_Strategy, \
        # cwe_rels_mitigation_Effectiveness, cwe_rels_cve, cwe_rels_capec, cwe_rels_DetectionMethods, cwe_rels_DetectionDescription, \
        # cwe_rels_DetectionEffectiveness, cwe_rels_impact, cwe_rels_impact_scope, cwe_rels_impact_note, cwe_rels_impact_Likelihood, \
        # cwe_rels_cweversion = self.read_nodescwe()[1]
        #capec节点读取
        capecnodelist=self.read_nodescapec()[0]
        capecrelationlist=self.read_nodescapec()[1]
        allnodelist.append(capecnodelist);allrelationlist.append(capecrelationlist)
        # capecID,capecVersion,capecLikelihood,capecSeverity, capecSeverityScope, capecAttackStepDes, \
        # capecAttackPhase,capecAttackTechnique,capecPrerequisites,capecSkillsRequired,capecResourcesRequired,capecScope,\
        # capecImpact,capecImpactnote=self.read_nodescapec()[0]
        # capec_rels_capec, capec_rels_capecVersion, capec_rels_Likelihood, capec_rels_Severity, capec_rels_AttStepDes, \
        # capec_rels_AttStepDes_Phase, capec_rels_AttStepDes_Technique, capec_rels_Prerequisites, capec_rels_SkillsRequired, \
        # capec_rels_ResourcesRequired, capec_rels_Impact, capec_rels_Impact_scope, capec_rels_Impact_note, capec_rels_Mitigation, \
        # capec_rels_cwe, capec_rels_Severity_Scope = self.read_nodescapec()[1]


        #cve节点建立

        print("开始创建节点：cve_id")
        self.create_node('cve_id',cveid)
        self.create_node('product', cveproduct)
        self.create_node('product_version', cveproduct)
        self.create_node('vendor',cvevendor )
        print("开始创建节点：product_type")
        self.create_node('product_type', cveproducttype)
        self.create_node('cvss_version', cvssversin)
        self.create_node('attack_vector', cveattackvector)
        self.create_node('attack_complexity',cveattackComplexity )
        self.create_node('privileges_required',cveprivilegesRequired )
        self.create_node('userInteraction',userInteraction )
        print("开始创建节点：confidentiality_impact")
        self.create_node('confidentiality_impact', confidentialityImpact)
        self.create_node('integrity_impact', integrityImpact)
        self.create_node('availability_impact', availabilityImpact)
        self.create_node('cvss_score', cvssbaseScore)
        self.create_node('severity',baseSeverity )
        print("开始创建节点：exploitability_score")
        self.create_node('exploitability_score', exploitabilityScore)
        self.create_node('impact_score', impactScore)
        self.create_node('published_date', publishedDate)
        self.create_node('version',cveversion )
        self.create_node('scope',cveScope )
        #cwe节点建立
        print("开始创建节点：cwe_id")
        self.create_node('cwe_id', cweid);self.create_node('scope',cwescope);self.create_node('consequence',cweimpact);self.create_node('likelihood', cweimpactLikelihood);
        self.create_node('note',cweimpactnote);self.create_node('version',cweversion);self.create_node('likelihood',cwelikelihood);self.create_node('mitigation',cwemitigation);
        self.create_node('phase', cwemitigationphase);self.create_node('strategy',cwemitigationStrategy);self.create_node('effectiveness',cwemitigationEffectiveness);self.create_node('detection_methods',cweDetectionMethods);
        self.create_node('description', cweDetectionDescription);self.create_node('effectiveness',cweDetectionEffectiveness)
        #capec节点建立
        print("开始创建节点：capec_id")
        self.create_node('capec_id', capecID);self.create_node('version', capecVersion);self.create_node('likelihood', capecLikelihood);self.create_node('severity', capecSeverity);
        self.create_node('severity', capecSeverityScope);self.create_node('attack_step', capecAttackStepDes);self.create_node('phase', capecAttackPhase);self.create_node('technique', capecAttackTechnique);
        self.create_node('prerequisites', capecPrerequisites);self.create_node('skills_required', capecSkillsRequired);self.create_node('resources_required', capecResourcesRequired);self.create_node('scope', capecScope);
        self.create_node('consequence', capecImpact);self.create_node('note', capecImpactnote)
        print('***************节点建立完成***************')
    def create_node_relationship(self,nodelabellist,nodeslist,relabellist,relist):
        nodelists=[];relists=[]
        print("***************创建nodelists***************")
        for i in range(len(nodelabellist)):
            nodelists.append(self.create_node(nodelabellist[i],nodeslist[i]))
        print("***************创建relists***************")
        for i in range(len(relabellist)):
            relists.append(self.create_relationship())
    def create_node(self, label, nodes):
        nodes=list(nodes)
        count = 0
        nodes_list = []  # 一批节点数据
        if(isinstance(nodes[0],list)==0):
            for node_name in nodes:
                node = Node(label, name=node_name)
                nodes_list.append(node)
        else:
            if (label == 'cve_id'):
                propertylist = ['description']
                for node_name in nodes:
                    node=Node(label, name=node_name[0],description=node_name[1])
                    nodes_list.append(node)
            elif(label=='capec_id'):
                propertylist=['title','abstraction','description']
                for node_name in nodes:
                    node=Node(label, name=node_name[0],title=node_name[1],abstraction=node_name[2],description=node_name[3])
                    nodes_list.append(node)
            elif(label=='cwe_id'):
                propertylist=['title','abstraction','description','extend_description']
                for node_name in nodes:
                    node=Node(label, name=node_name[0],title=node_name[1],abstraction=node_name[2],description=node_name[3],extend_description=node_name[4])
                    nodes_list.append(node)
            elif(label=='attack_step'):
                propertylist=['step']
                for node_name in nodes:
                    node=Node(label, name=node_name[0],step=node_name[1])
                    nodes_list.append(node)
            elif (label == 'skills_required'):
                propertylist = ['level']
                for node_name in nodes:
                    node=Node(label, name=node_name[0],level=node_name[1])
                    nodes_list.append(node)
        self.batch_create(nodes_list,[])
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
    def create_relationship(self, start_node, end_node, edges, rel_type):
        count=0
        relations_list = []  # 一批关系数据
        if (len(edges[0]) == 2):
            for edge in edges:
                count+=1
                print("关系个数添加中",count,len(edges))
                pnode= self.g.nodes.match(start_node, name=edge[0]).first()
                qnode= self.g.nodes.match(end_node, name=edge[1]).first()
                relation = Relationship(pnode, rel_type, qnode)
                relations_list.append(relation)
        elif (len(edges[0]) == 3):
            for edge in edges:
                pnode= self.g.nodes.match(start_node, name=edge[0]).first()
                qnode= self.g.nodes.match(end_node, name=edge[2]).first()
                relation = Relationship(pnode, edge[1], qnode)
                relations_list.append(relation)
        self.batch_create([], relations_list)
        return
        # all = len(edges)
        # for edge in edges:
        #     if(len(edge)==2):
        #         p = edge[0]
        #         q = edge[1]
        #         query = "match(p:%s),(q:%s) where p.name='%s'and q.name='%s' merge(p)-[rel:%s{name:'%s'}]->(q)" % (
        #             start_node, end_node, p, q, rel_type, rel_name)
        #         try:
        #             self.g.run(query)
        #             count += 1
        #             print(rel_type, count, all)
        #         except Exception as e:
        #             traceback.print_exc()
        #     elif(len(edge)==3):
        #         p = edge[0]
        #         q = edge[-1]
        #         query = "match(p:%s),(q:%s) where p.name='%s'and q.name='%s' merge(p)-[rel:%s{name:'%s'}]->(q)" % (
        #             start_node, end_node, p, q, edge[1], edge[1])
        #         try:
        #             self.g.run(query)
        #             count += 1
        #             print(rel_type, count, all)
        #         except Exception as e:
        #             traceback.print_exc()
        # return
    def batch_create(self, nodes_list, relations_list):
        """
            批量创建节点/关系,nodes_list和relations_list不同时为空即可
            特别的：当利用关系创建节点时，可使得nodes_list=[]
        :param graph: Graph()
        :param nodes_list: Node()集合
        :param relations_list: Relationship集合
        :return:
        """
        subgraph = Subgraph(nodes_list, relations_list)
        tx_ = self.g.begin()
        tx_.create(subgraph)
        tx_.commit()
if __name__ == '__main__':
    handler = SecurityGraph()
    print('***************建立节点中***************')
    handler.create_nodes()
    # print('***************建立关系中***************')
    # handler.create_relationships()

import json
import hashlib
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import binascii

def key_generate() :
    key=DSA.generate(1024)
    return key

def tup_generate(key) :
    return [key.y, key.g, key.p, key.q]

#앨리스, 밥 키 생성
A_key = key_generate()
A_tup = tup_generate(A_key)
A_pub = DSA.construct(A_tup)

B_key = key_generate()
B_tup = tup_generate((B_key))
B_pub= DSA.construct(B_tup)

# create block 0
fw = open("Block0.json","w+")
genblock = json.dumps(
    {"TxID": 0, "Hash": "This is the genesis block", "Nonce": 0, "Output": [ {"Value" : 10, "ScriptPubKey": (A_pub.export_key().decode('utf-8'))+" OP_CHECKSIG"}]}, indent=4, separators=(',', ': '))
fw.write(genblock)
fw.close()


def indexcheck(msg, A_pub) : #output 중에 어떤 것이 맞는지 선택 , alice가 서명하므로 alice의 public key 와 일치하는 output 찾기
    cnt=0;
    #print(len(msg))
    for i in msg:
        sp = i["ScriptPubKey"].split(" OP_CHECKSIG")
        if(sp[0]==(A_pub).export_key().decode('utf-8')):
            return cnt
        cnt+=1

def verify(msg, signature, hash_obj) :
    sp=msg.split(" OP_CHECKSIG")
    st=[]
    st.append(signature) # push sig
    for i in range(len(sp)-1):
        st.append(sp[i]) # push output(A_pub, "OP_CHECKSIG")
    st.append("OP_CHECKSIG")
    while len(st)!=0:
        str= st.pop()
        if(str == "OP_CHECKSIG") :
            msgpk=DSA.import_key(st.pop())
            sig=st.pop()
            verifier = DSS.new(msgpk, 'fips-186-3')
            verifier.verify(hash_obj, sig)
            try:
                verifier.verify(hash_obj, signature)
                return True
            except ValueError:
                return False
    return False

for tr in range(11): # 0~10 실행 1~10 블록 생성
    #이전 블록 정보 읽기
    fr = open("Block" + str(tr) + ".json","r")
    data = fr.read()
    fr.close()
    json_data=json.loads(data) #전 블록 데이터 json 형식으로 load
    print(json.dumps(json_data, indent=4))

    if(tr==10):
        break
    o_hash = SHA256.new(data.encode())

    index=indexcheck(json_data['Output'], A_pub) #A_pubkey 와 대응하는 index가 몇 번인지 찾기
    #전자서명
    signer = DSS.new(A_key, 'fips-186-3')
    signature = signer.sign(o_hash)
    if(verify(json_data["Output"][index]["ScriptPubKey"], signature, o_hash)) :
        alice_val= int(json_data["Output"][index]["Value"])-1
        if(len(json_data["Output"])<2) :
            bob_val=1
        else :
            bob_val= int(json_data["Output"][(index+1)%2]["Value"])+1
        nonce=0
        while 1:
            tx = json.dumps({"TxID": tr+1, "Hash": o_hash.hexdigest(), "Nonce": nonce, "Output": [ {"Value" : bob_val, "ScriptPubKey": (B_pub.export_key().decode('utf-8'))+" OP_CHECKSIG"}, {"Value" : alice_val, "ScriptPubKey": (A_pub.export_key().decode('utf-8'))+" OP_CHECKSIG"}]}, indent=4, separators=(',', ': '))
            if(int(hashlib.sha256((tx).encode()).hexdigest(), 16) < 2**248):
                fw = open("Block" + str(tr+1) + ".json","w+")
                fw.write(tx)
                fw.close()
                break
            nonce+=1

#hash 값 체크하기
for tr in range(10):
    #이전 블록 정보 읽기
    fr = open("Block" + str(tr) + ".json","r")
    data = fr.read()
    fr.close()
    o_hash = SHA256.new(data.encode())


    fr = open("Block" + str(tr+1) + ".json","r")
    data2 = fr.read()
    fr.close()
    json_data2=json.loads(data2) #전 블록 데이터 json 형식으로 load

    print(o_hash.hexdigest() == json_data2["Hash"])

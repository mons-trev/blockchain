**Blockchain Application**

**Object**

1. Create the public/private keys for Alice and Bob. Use DSA with 1024 bits for the digital signature.

```python
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

```
Crypto module을 이용하여 alice와 bob의 키를 생성해주었습니다. key_generate()로 key를 생성해주었고, tup_generate로 생성된 키
로 y,g,p,q 튜플을 생성해주었습니다. 또한 alice와 bob의 키로 alice의 public key, bob의 public key를 생성해주었습니다.

2. The system has an initial block (a genesis block) to start the transaction.
```python
# create block 0
fw = open("Block0.json","w+")
genblock = json.dumps(
    {"TxID": 0, "Hash": "This is the genesis block", "Nonce": 0, "Output": [ {"Value" : 10, "ScriptPubKey": (A_pub.export_key().decode('utf-8'))+" OP_CHECKSIG"}]}, indent=4, separators=(',', ': '))
fw.write(genblock)
fw.close()

```
Block0.json  파일에 위의 정보를 저장합니다.

3. Create the blocks (block1.txt ~ block10.txt) that Alice sends 1 coin to Bob from its account in each block until she sends all she has.

```python
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
```

위의 for문을 하나씩 돌 때마다, 다음 블록을 생성합니다.
while 문의 절차를 보면, 이전 블록의 정보를 읽어들이고 출력합니다. 따라서 출력창에는 0~10 번의 블록이 출력됩니다.
o_hash는 이전 블록의 해시입니다. hexdigest()를 하지 않은 값이기에 original의 뜻을 붙여 o_hash라고 명칭했습니다.
몇번째 output 과 대응되는지 알기 위해, index를 찾는 함수를 호출합니다. indexcheck() 함수는 아래에서 다루도록하겠습니다.
alice가 돈을 보내므로 output을 unlock 해야되기 때문에 alice의 key로 signer를 만든 뒤, 이전 블록을 해시한 것을 서명합니다.
verify() 함수를 통해 전자 서명을 인증을합니다. verify() 함수 또한 아래에서 다루겠습니다.
서명 인증이 통과하면 이전 블록에 있던 alice의 value 와 bob의 value를 추출합니다. 이 때, block 1을 만들 경우, block 0 엔 bob의
value가 없으므로 if 문으로 1로 초기화를 해줍니다.
nonce를 처음에 0으로 설정을 해주고 proof of work를 해줍니다. while 문을 돌려가며 현재 block의 nonce를 하나씩 올리고 해싱한 값이
2^248 보다 작다면 현재 블록을 파일에 등록합니다.

```python
def indexcheck(msg, A_pub) : #output 중에 어떤 것이 맞는지 선택 , alice가 서명하므로 alice의 public key 와 일치하는 output 찾기
    cnt=0;
    #print(len(msg))
    for i in msg:
        sp = i["ScriptPubKey"].split(" OP_CHECKSIG")
        if(sp[0]==(A_pub).export_key().decode('utf-8')):
            return cnt
        cnt+=1
```
위에서 언급한 indexcheck의 함수입니다. msg는 이전 블록의 output(1개~2개) 이며, A_pub 은 alice가 돈을 보내고 전자서명을 하기 때
문에 alice의 publickey를 의미합니다. cnt는 output의 몇 번째 index인지를 의미하는 return 값입니다.
output list 중에서 A_pub 과 일치하는 output의 public key가 몇번째 인덱스인지를 찾습니다. 이 때, ouput의 publickey는 문자열이므로
DSA.import_key() 함수를 사용합니다.

```python
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
```

마지막으로 위에서 언급한 verify() 함수입니다. msg는 이전 블록의 output을 의미합니다. 이때 output은 위의 checkindex()에서 도출한 인덱스 값의 output입니다. signature은 alice가 이전 block을 서명한 값이며 hash_obj는 이전 블록의 해시입니다.

<p align="center">
  <img src="https://github.com/user-attachments/assets/145bda38-3240-45ea-981a-fd56b74c91e2" alt="image">
</p>


위 사진의 구조를 구현하기 위해 stack 자료구조를 이용했습니다. output을 의미하는 msg를 publickey, op_checksig로 분리해준 뒤,
st(stack) 에 signature, publickey, “OP_CHECKSIG” 를 넣어줍니다.
스택이 비어있을 때까지 pop()을 합니다. “OP_CHECKSIG” 명령어를 만난다면 이미 들어가있는 output의 publickey와 signature를 각각
msgpk, sig 에 넣어줍니다. msgpk로 verifier를 설정해주고, 이전 블록의 해싱한 값과 이전 블록을 서명한 값으로 서명 인증을 합니다.
authentic 하다면 true를 return 하고 아니라면 false를 return 합니다.

```python
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

```
전체 코드는 위와 같으며, 출력은 0~10 block 의 json 값이 나올 것 입니다.
밑의 hash 값 체크하기 코드는 이전 블록의 해싱된 값이 현재 블록의 Hash 에 잘 담겼는지 확인하는 절차입니다. 잘 작동된다면 10개의
true가 출력될 것입니다.


출력물
```json
{
    "TxID": 0,
    "Hash": "This is the genesis block",
    "Nonce": 0,
    "Output": [
        {
            "Value": 10,
            "ScriptPubKey": "-----BEGIN PUBLIC KEY-----\nMIIBtjCCASsGByqGSM44BAEwggEeAoGBAOXm6AFaOspc5AsKP6QHePDefDTKu7D1\nvN/l98PmuCWMVnmxy9FTr6aH9IMBERKkingbn+R5Blb+1PtCyRbe7yU3ND8B9vPP\nZHPcfRMJWKWqTT/UAk8ySMVaL5Em996/8eeFNse0FGS35imtFuLWur1efg+5GMNC\nx+02ATRqMnrlAhUArHDjoQG8fZLNiBCA3sQTcz5AvoECgYBAfJh8LeoigKnSCdxJ\nvCQ3j6gw8r3ZYI9GZJ++6igh7hSEuIfcpgFbN5S/mAiDIFDEJ1G9ysl98ZswlO3J\nDxteOwZ3QKHi0th23S/i1zsExLyzkRodWgzS7s0NePBYEkGdd6PHn2dCYC/rpYYg\nqptiE+cZJtYXOOLR8Ril8x4stgOBhAACgYBccnwJtvTexa6QIIBo+XTP3FK90qJt\n0ql4gc4jwroErrHOjh4oujS74UUOFR1/pPvBn97G1356BqAHcLIhvSjn5vmoQG+l\nwpftVkpsHKq/aF5KpkrUJKiT5tWUmbKmNhMdAgdlQFlitWgR1rofJNQylqo0z4Ix\ndRS9WRaPf2PmOg==\n-----END PUBLIC KEY----- OP_CHECKSIG"
        }
    ]
}
{
    "TxID": 1,
    "Hash": "93a1a2856e6fe59113e2f742aa49b5548c305daf0fc126bc88ee668b25167414",
    "Nonce": 23,
    "Output": [
        {
            "Value": 1,
            "ScriptPubKey": "-----BEGIN PUBLIC KEY-----\nMIIBuDCCASwGByqGSM44BAEwggEfAoGBAPjt87xg7Iwox2VOfg3zZrclJ3p+vXdU\nYkd0RmEBVBAcRqRpNl+CQmUHMbEgGrykAMem3VVpIXPyOZHS4eQFRd/W6r+fkOFx\nQYOkpeJprQdvwrvenOP8mBxFDgkToSqUG7M3ayXcu89EOfzkfSmVq2+yWuagszo+\n5tlgENc5nbwzAhUAmYvQ2xcnpr4vGWdMwbZGIZy0POsCgYEAqZpz4FhHyOWSpy7h\nzAJ7S5tgLQ9XkHMoHUU/IXzUATTW4CG+6NTCA9lm+9Dwdr8rZlCvS7hpcoRiOmzw\nPgNvLUJw4D5MBRWe/i73g69hJkd14Dzy06+I8ohuoBcju6lzT2BqqeUmrS3um2Qd\ngM/R5jihs6jSO59mK9TLaSNZUyQDgYUAAoGBAKfhkzoHR/ml2zJNdnwT/L3yvzJ+\n4ZQThSJP/F9bzROflrM+i4/pMDQCGygmvyKnYxPytQJmauEgWEE5KoBvrugA2Upa\nAp/V6eSybRMwXs2oEYDcLAVOddaEKN938VoU9nFq5FsuOSYRzNQ+3HAQAS0WEh00\nq/ORXNXyNGatmhnz\n-----END PUBLIC KEY----- OP_CHECKSIG"
        },
        {
            "Value": 9,
            "ScriptPubKey": "-----BEGIN PUBLIC KEY-----\nMIIBtjCCASsGByqGSM44BAEwggEeAoGBAOXm6AFaOspc5AsKP6QHePDefDTKu7D1\nvN/l98PmuCWMVnmxy9FTr6aH9IMBERKkingbn+R5Blb+1PtCyRbe7yU3ND8B9vPP\nZHPcfRMJWKWqTT/UAk8ySMVaL5Em996/8eeFNse0FGS35imtFuLWur1efg+5GMNC\nx+02ATRqMnrlAhUArHDjoQG8fZLNiBCA3sQTcz5AvoECgYBAfJh8LeoigKnSCdxJ\nvCQ3j6gw8r3ZYI9GZJ++6igh7hSEuIfcpgFbN5S/mAiDIFDEJ1G9ysl98ZswlO3J\nDxteOwZ3QKHi0th23S/i1zsExLyzkRodWgzS7s0NePBYEkGdd6PHn2dCYC/rpYYg\nqptiE+cZJtYXOOLR8Ril8x4stgOBhAACgYBccnwJtvTexa6QIIBo+XTP3FK90qJt\n0ql4gc4jwroErrHOjh4oujS74UUOFR1/pPvBn97G1356BqAHcLIhvSjn5vmoQG+l\nwpftVkpsHKq/aF5KpkrUJKiT5tWUmbKmNhMdAgdlQFlitWgR1rofJNQylqo0z4Ix\ndRS9WRaPf2PmOg==\n-----END PUBLIC KEY----- OP_CHECKSIG"
        }
    ]
}
{
    "TxID": 2,
    "Hash": "0081ace11b53db52665bb3b4794f4ffdbb8dea84d2608b90a82e9d21d3283ee5",
    "Nonce": 4,
    "Output": [
        {
            "Value": 2,
            "ScriptPubKey": "-----BEGIN PUBLIC KEY-----\nMIIBuDCCASwGByqGSM44BAEwggEfAoGBAPjt87xg7Iwox2VOfg3zZrclJ3p+vXdU\nYkd0RmEBVBAcRqRpNl+CQmUHMbEgGrykAMem3VVpIXPyOZHS4eQFRd/W6r+fkOFx\nQYOkpeJprQdvwrvenOP8mBxFDgkToSqUG7M3ayXcu89EOfzkfSmVq2+yWuagszo+\n5tlgENc5nbwzAhUAmYvQ2xcnpr4vGWdMwbZGIZy0POsCgYEAqZpz4FhHyOWSpy7h\nzAJ7S5tgLQ9XkHMoHUU/IXzUATTW4CG+6NTCA9lm+9Dwdr8rZlCvS7hpcoRiOmzw\nPgNvLUJw4D5MBRWe/i73g69hJkd14Dzy06+I8ohuoBcju6lzT2BqqeUmrS3um2Qd\ngM/R5jihs6jSO59mK9TLaSNZUyQDgYUAAoGBAKfhkzoHR/ml2zJNdnwT/L3yvzJ+\n4ZQThSJP/F9bzROflrM+i4/pMDQCGygmvyKnYxPytQJmauEgWEE5KoBvrugA2Upa\nAp/V6eSybRMwXs2oEYDcLAVOddaEKN938VoU9nFq5FsuOSYRzNQ+3HAQAS0WEh00\nq/ORXNXyNGatmhnz\n-----END PUBLIC KEY----- OP_CHECKSIG"
        },
        {
            "Value": 8,
            "ScriptPubKey": "-----BEGIN PUBLIC KEY-----\nMIIBtjCCASsGByqGSM44BAEwggEeAoGBAOXm6AFaOspc5AsKP6QHePDefDTKu7D1\nvN/l98PmuCWMVnmxy9FTr6aH9IMBERKkingbn+R5Blb+1PtCyRbe7yU3ND8B9vPP\nZHPcfRMJWKWqTT/UAk8ySMVaL5Em996/8eeFNse0FGS35imtFuLWur1efg+5GMNC\nx+02ATRqMnrlAhUArHDjoQG8fZLNiBCA3sQTcz5AvoECgYBAfJh8LeoigKnSCdxJ\nvCQ3j6gw8r3ZYI9GZJ++6igh7hSEuIfcpgFbN5S/mAiDIFDEJ1G9ysl98ZswlO3J\nDxteOwZ3QKHi0th23S/i1zsExLyzkRodWgzS7s0NePBYEkGdd6PHn2dCYC/rpYYg\nqptiE+cZJtYXOOLR8Ril8x4stgOBhAACgYBccnwJtvTexa6QIIBo+XTP3FK90qJt\n0ql4gc4jwroErrHOjh4oujS74UUOFR1/pPvBn97G1356BqAHcLIhvSjn5vmoQG+l\nwpftVkpsHKq/aF5KpkrUJKiT5tWUmbKmNhMdAgdlQFlitWgR1rofJNQylqo0z4Ix\ndRS9WRaPf2PmOg==\n-----END PUBLIC KEY----- OP_CHECKSIG"
        }
    ]
}

...

True
True
True
True
True
True
True
True
True
True
Process finished with exit code 0
```

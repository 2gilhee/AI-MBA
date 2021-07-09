import ecdsa
import hashlib
from timeit import default_timer as timer
from datetime import timedelta

# 공개키와 개인키 생성
private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
public_key = private_key.get_verifying_key()

print('private key: 0x'+private_key.to_string().hex())
print('public key: 0x'+public_key.to_string().hex())


# 파일에서 메시지 읽기
f1 = open("Original_message.txt", 'r')
message = f1.readline()

f2 = open("Fake_message.txt", 'r')
fake_message = f2.readline()


# 메시지 해시값 구하기
hash_message = hashlib.sha256()
hash_message.update(message.encode())
hash_message.hexdigest()

hash_fake_message = hashlib.sha256()
hash_fake_message.update(fake_message.encode())
hash_fake_message.hexdigest()


# 서명하기
signature = private_key.sign(hash_message.digest())


# 서명 검증
print()
print('정상 메세지로 서명을 검증할 때')
try:
    public_key.verify(signature, hash_message.digest())
    print('verified')
except ecdsa.BadSignatureError:
    print('not verified')

print('비정상 메세지로 서명을 검증할 때')
try:
    public_key.verify(signature, hash_fake_message.digest())
    print('verified')
except ecdsa.BadSignatureError:
    print('not verified')


print()
# 서명 및 서명 시간 측정
# 해시값이 아닌 메시지에 서명한 후 시간 측정
start_without_hash = timer()
signature_without_hash = private_key.sign(message.encode())
end_without_hash = timer()
print('Time taken to sign the message without hash: ', timedelta(seconds=end_without_hash-start_without_hash))

# 메시지 해시값에 서명한 후 시간 측정
start_with_hash = timer()
signature_with_hash = private_key.sign(hash_message.digest())
end_with_hash = timer()
print('Time taken to sign the message with hash: ', timedelta(seconds=end_with_hash-start_with_hash))
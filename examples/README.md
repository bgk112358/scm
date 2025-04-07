# 建立 SSL 服务端

openssl s_server -accept 127.0.0.1:4433 \
-enc_cert test_certs/double_cert/SE.cert.pem \
-enc_key test_certs/double_cert/SE.key.pem \
-sign_cert test_certs/double_cert/SS.cert.pem \
-sign_key test_certs/double_cert/SS.key.pem \
-enable_ntls

openssl s_client -connect 127.0.0.1:4433 -cipher ECC-SM2-WITH-SM4-SM3 -enable_ntls -ntls

export LD_LIBRARY_PATH=/Users/sm2/dependencies/Tongsuo-8.3.3/build/lib
./openssl s_server -accept 127.0.0.1:4433 -enc_cert client.pem -enc_key client.key -sign_cert client.pem -sign_key client.key -enable_ntls
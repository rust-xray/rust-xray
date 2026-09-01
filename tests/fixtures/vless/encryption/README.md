# Go-derived CommonConn traffic golden vectors
#
# Source: Xray-core @ 5e245b082e6be8c8899c34410f488e8ab001aaba
# Package: proxy/vless/encryption/common.go (NewAEAD + CommonConn.Write)
#
# Inputs:
#   united[0]=0x01, united[32]=0x02, united[64]=0x03
#   context = "golden-traffic-context-1234567890"
#   plaintext = "vless-traffic-plaintext"
#   initial nonce = 00..00 (IncreaseNonce before first Seal)
#
# AES frame (prefer_aes=true):
#   header: 1703030027
#   ciphertext+tag: 40751f2b0d052a5050b809e607a5f05a55bda0c172d90cb463ec3d55c603313ace0f3e5d9b2794
#
# ChaCha frame (prefer_aes=false):
#   header: 1703030027
#   ciphertext+tag: ec82862fcbdb1f8560bcf8d51f2acb4ff7f62e4e5ba19840b216b763cdc97be083f67d9c6c0b76
#
# Rust regression: tests/unit/vless/encryption/go_traffic_golden.rs

#!/bin/sh

rm -rf .pki/
rm bob* alice* example*
./skgu_pki init
./skgu_pki cert -g alice.priv alice.pub alice
./skgu_pki cert -g bob.priv bob.pub bob
./skgu_nidh alice.priv alice.cert alice bob.pub bob.cert bob example
cat example
rm example
./skgu_nidh bob.priv bob.cert bob alice.pub alice.cert alice example
cat example
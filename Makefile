iot-cert:
	curl -O https://pki.goog/roots.pem && \
	openssl genrsa -out rsa_private.pem 2048 && \
	openssl rsa -in rsa_private.pem -pubout -out rsa_public.pem && \
	echo "Add me to IoT Core" && \
	cat rsa_public.pem

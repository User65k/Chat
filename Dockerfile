FROM alpine:3.9

RUN apk add --no-cache python3 openssl

COPY chat.py /home/
COPY dhparam.pem /home/

WORKDIR /home

EXPOSE 1337

ENTRYPOINT ["python3", "chat.py"]
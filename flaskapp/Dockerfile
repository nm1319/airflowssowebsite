# syntax=docker/dockerfile:1.4
FROM python:3.10-slim-buster

#ARG DEV_APT_DEPS="apt-transport-https apt-utils build-essential ca-certificates dirmngr freetds-bin freetds-dev git gosu graphviz graphviz-dev ldap-utils libffi-dev libkrb5-dev libldap2-dev libleveldb1d libleveldb-dev libsasl2-2 libsasl2-dev libsasl2-modules libssl-dev locales lsb-release openssh-client sasl2-bin software-properties-common sqlite3 sudo unixodbc unixodbc-dev pkg-config libxml2-dev libxmlsec1-dev libxmlsec1-openssl"

#RUN apt-get update \
#    && apt-get install -y --no-install-recommends ${DEV_APT_DEPS}

WORKDIR /demo

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED='sample'
#ENV API_BASE='https://127.0.0.1:9031' \
#    CLIENT_ID='airflow_oauth' \
#    CLIENT_SECRET='TQ7nhp0NgCdbtNde5zTpTT8ExzvHsMc9H60nSoa10FyrbIHyZEL1m89ct0sLzSfu' \
#    REDIRECT_URI='https://127.0.0.1/redirect'

EXPOSE 5000

CMD [ "python3", "-m" , "app", "run", "--host=0.0.0.0"]

 
# syntax=docker/dockerfile:1.4

FROM python:3.10.13-bullseye as build

USER root

ARG AIRFLOW_HOME=/opt/airflow
ARG AIRFLOW_UID="50000"
ARG AIRFLOW_USER_HOME_DIR=/home/airflow
ARG AIRFLOW_VERSION="2.7.3"
ARG OAUTH_APP_ID=""
ARG OAUTH_APP_SECRET=""

#ARG PYTHON_VERSION="3.10"
#ARG PYTHON_VERSION='$(python --version | cut -d " " -f 2 | cut -d "." -f 1-2)'
#ARG CONSTRAINT_URL=https://raw.githubusercontent.com/apache/airflow/constraints-${AIRFLOW_VERSION}/constraints-${PYTHON_VERSION}.txt

RUN adduser --gecos "First Last,RoomNumber,WorkPhone,HomePhone" --disabled-password \
           --quiet "airflow" --uid "${AIRFLOW_UID}" --gid "0" --home "${AIRFLOW_USER_HOME_DIR}" && \
    mkdir -p ${AIRFLOW_HOME} && chown -R "airflow:0" "${AIRFLOW_USER_HOME_DIR}" ${AIRFLOW_HOME}

#COPY entrypoint_prod.sh /entrypoint
#RUN chmod a+rx /entrypoint

RUN mkdir -pv "${AIRFLOW_HOME}" \
    && mkdir -pv "${AIRFLOW_HOME}/dags" \
    && mkdir -pv "${AIRFLOW_HOME}/logs" \
    && chown -R airflow:0 "${AIRFLOW_USER_HOME_DIR}" "${AIRFLOW_HOME}" \
    && chmod -R g+rw "${AIRFLOW_USER_HOME_DIR}" "${AIRFLOW_HOME}" \
    && find "${AIRFLOW_HOME}" -executable -print0 | xargs --null chmod g+x \
    && find "${AIRFLOW_USER_HOME_DIR}" -executable -print0 | xargs --null chmod g+x


USER airflow

#RUN pip install --no-cache-dir xmlsec apache-airflow python3-saml
#RUN pip install --no-cache-dir xmlsec python3-saml psycopg2 isodate
#RUN pip install --force-reinstall --no-binary lxml lxml
#RUN pip install --no-cache-dir "apache-airflow==${AIRFLOW_VERSION}" --constraint "${CONSTRAINT_URL}"
RUN pip install --no-cache-dir "apache-airflow==${AIRFLOW_VERSION}"
COPY requirements.txt /
RUN pip install --no-cache-dir --user -r /requirements.txt

#COPY --chown=airflow:0 airflow-saml-auth-plugin/plugins /opt/airflow/plugins/
#COPY --chown=airflow:0 settings.json /opt/airflow/
COPY --chown=airflow:0 webserver_config.py /opt/airflow/

# ARG AIRFLOW__API__AUTH_BACKEND=airflow.api.auth.backend.default
#ARG AIRFLOW__SAML_AUTH__SAML_PATH=/opt/airflow


ENV PATH=${PATH}:${AIRFLOW_USER_HOME_DIR}/.local/bin:/opt/airflow/plugins \
    AIRFLOW_USER_HOME_DIR=${AIRFLOW_USER_HOME_DIR} \
    AIRFLOW_HOME=${AIRFLOW_HOME} \
    AIRFLOW_UID=${AIRFLOW_UID} \
    AIRFLOW__WEBSERVER__BASE_URL=''   \
#    AIRFLOW__API__AUTH_BACKEND=${AIRFLOW__API__AUTH_BACKEND} \
#    AIRFLOW__API__AUTH_BACKENDS="airflow.api.auth.backend.default" \
#    AIRFLOW__SAML_AUTH__SAML_PATH=${AIRFLOW__SAML_AUTH__SAML_PATH} \
    PYTHONPATH="/opt/airflow/plugins" \
    OAUTH_APP_ID=${OAUTH_APP_ID} \
    OAUTH_APP_SECRET=${OAUTH_APP_SECRET}


EXPOSE 8080

CMD [ "airflow", "standalone" ]
#ENTRYPOINT ["/usr/bin/dumb-init", "--", "/entrypoint"]
#CMD []

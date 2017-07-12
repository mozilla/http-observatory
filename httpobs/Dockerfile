# http-observatory

FROM python:3.5
MAINTAINER https://github.com/mozilla/http-observatory

RUN groupadd --gid 1001 app && \
    useradd --uid 1001 --gid 1001 --shell /usr/sbin/nologin app
RUN install -o app -g app -d /var/run/httpobs /var/log/httpobs

WORKDIR /app

COPY . httpobs

RUN pip install --upgrade --no-cache-dir \
    -r httpobs/requirements.txt \
    -r httpobs/database/requirements.txt \
    -r httpobs/scanner/requirements.txt \
    -r httpobs/website/requirements.txt

ENV PYTHONPATH $PYTHONPATH:/app

USER app

# http-observatory

FROM python:3.11
MAINTAINER https://github.com/mozilla/http-observatory

RUN groupadd --gid 1001 app && \
    useradd --uid 1001 --gid 1001 --shell /usr/sbin/nologin app
RUN install -o app -g app -d /var/run/httpobs /var/log/httpobs

WORKDIR /app

COPY pyproject.toml poetry.lock .
RUN pip install poetry && \
    poetry config virtualenvs.create false && \
    poetry install

COPY httpobs httpobs
RUN poetry install --no-dev

ENV PYTHONPATH $PYTHONPATH:/app

USER app

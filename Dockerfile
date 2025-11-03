FROM python:3.12-alpine AS base
RUN apk update && apk add --no-cache \
    gcc \
    musl-dev \
    openjpeg-dev \
    jpeg-dev \
    swig \
    make \
    g++ \
    clang-dev
WORKDIR /code
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY src src

FROM base AS test
COPY test_requirements.txt .coveragerc ./
RUN pip install -r test_requirements.txt
COPY tests tests

FROM base AS build
CMD [ "python", "src/validate.py" ]
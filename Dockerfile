FROM golang:1.8
RUN go get -u github.com/govend/govend
COPY . /go/src/github.com/dustin-decker/saml-proxy
WORKDIR /go/src/github.com/dustin-decker/saml-proxy
RUN govend -v
RUN go install
RUN rm -rf /go/src/github.com/dustin-decker/saml-proxy
COPY config.yaml /
WORKDIR /
EXPOSE 9090
#RUN adduser -D -u 59999 -s /usr/sbin/nologin user
#USER 59999
CMD ["saml-proxy"]

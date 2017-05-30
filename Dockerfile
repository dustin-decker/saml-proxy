FROM golang:1.8
RUN go get -u github.com/govend/govend
COPY . /go/src/github.com/sevoma/SzechuanSauce
WORKDIR /go/src/github.com/sevoma/SzechuanSauce
RUN govend -v
RUN go install
RUN rm -rf /go/src/github.com/sevoma/SzechuanSauce
COPY config.yaml /
WORKDIR /
EXPOSE 9090
#RUN adduser -D -u 59999 -s /usr/sbin/nologin user
#USER 59999
CMD ["SzechuanSauce"]

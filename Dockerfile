FROM scratch
ADD ./build/ca /
ADD ./docs/swagger.json /docs/swagger.json
CMD ["/ca"]
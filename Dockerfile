FROM scratch
ADD ./build/ca /
CMD ["/ca"]

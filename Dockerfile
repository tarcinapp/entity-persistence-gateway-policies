FROM openpolicyagent/opa:0.24.0

COPY ./policies /policies
ENTRYPOINT ["/opa"]
CMD ["run"]